# -- coding: utf-8 --**
import nmap
import sys
import os
import time
import datetime
import traceback
import logging
import configparser
import json
from queue import Queue
import threading

tcp_port_list_file = "tcp_port_list.txt"
config_file = "config.ini"

result_dist = {}
sensitive_port_list = []
sensitive_service_list = []
warning_dict = {"info": []}

queue_mutex = threading.Lock()


class ScannedTaskConsumer(threading.Thread):
    def __init__(self, task_queue, scan_function, tcp_pts):
        threading.Thread.__init__(self)
        self.task_queue = task_queue
        self.exit_code = 0
        self.exc_traceback = ""
        self.exception = None
        self.executed_function = scan_function
        self.tcp_target_ports = tcp_pts
        self.scan_item = None
        self.flag = True

    def run(self):
        with queue_mutex:
            if not self.task_queue.empty():
                self.scan_item = self.task_queue.get()
                print("get" + self.scan_item)
            else:
                self.flag = False
        while self.flag:
            try:
                # raise Exception("test")
                self.executed_function(self.scan_item, self.tcp_target_ports)
                with queue_mutex:
                    if not self.task_queue.empty():
                        self.scan_item = self.task_queue.get()
                        print("get" + self.scan_item)
                    else:
                        self.flag = False
            except Exception as e:
                self.exit_code = 1
                self.exc_traceback = traceback.format_exc()
                self.exception = e
                return


# ========================================================
try:
    nm = nmap.PortScanner()
except nmap.PortScannerError:
    print("Nmap is not found", sys.exc_info()[0])
    sys.exit(0)


# ========================================================


# Parameter: -
# Parameter Type: -
# Description: Create a Folder for Logs if the Log Folder Doesn't Exist, Otherwise Do Nothing
def init_dir():
    folder_name = '/logs'
    current_directory = './'
    try:
        os.makedirs(current_directory + folder_name, exist_ok=True)
    except OSError:
        pass


# Parameter: config_filename
# Parameter Type: string
# Return: threads_num, scan_targets
# Return Type: int, list
# Description: Read the Content of the Config File, Including:
#              the IPs to Scan, Max Number of Threads for Scanning, Sensitive Ports, Names of the Sensitive Service
def read_config_from_ini_file(config_filename):
    config = configparser.ConfigParser()
    config.read(config_filename)
    threads_num = int(config["max_threads"]["num"])
    scan_targets = (config["scan_targets"]["targets"].split(","))
    for sensitive_port_item in (config["sensitive_ports"]["ports"].split(",")):
        sensitive_port_list.append(sensitive_port_item)
    for sensitive_services_item in (config["sensitive_services"]["service_name"].split(",")):
        sensitive_service_list.append(sensitive_services_item.lower())
    return threads_num, scan_targets


# Parameter: port_list_filename
# Parameter Type: string
# Return: file_content
# Return Type: string
# Description: Read the Content of The Port List File
def read_port_list_from_file(port_list_filename):
    with open(port_list_filename, "r", encoding="utf-8") as f:
        file_content = f.read()
    return file_content


# Parameter: tcp_file_content
# Parameter Type: string
# Return: separated_port_list
# Return Type: string
# Description: load the TCP file content, then separate the string into "T:..."
def tcp_file_content_parser(tcp_file_content):
    file_content_list = tcp_file_content.split("\n")
    tcp_port = "T:"
    for port_item in file_content_list:
        tcp_port += port_item + ","
    separated_port_list = tcp_port
    return separated_port_list[:-1]


# Parameter: scanned_target, scanned_port_list
# Parameter Type: string, string
# Description: Use SYN Scanning, which is more quickly than Normal TCP Scanning, "-sV" for Scanning Service Version
def single_ip_scan(scanned_target, tcp_port_list):
    tcp_result = nm.scan(scanned_target, ports=tcp_port_list, arguments="--max-rtt-timeout 500ms -Pn -T4 -n "
                                                                        "--min-parallelism 100 -sS -sV --min-rate 100")
    print(nm.command_line())
    result_dist[scanned_target] = tcp_result


# Parameter: scanned_target, scan_result
# Parameter Type: string - Key of the result_dist, PortScanner.scan() - Value of the result_dist
# Description: Output the Information of a Single Scan
def scan_result_output(scanned_target, scan_result):
    current_time = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    logger.info("----------")
    if scan_result["nmap"]["scanstats"]["downhosts"] == "1" \
            and scan_result["nmap"]["scanstats"]["uphosts"] == "0":
        logger.info(current_time + " IP : %s  主机状态: death" % scanned_target)
        return
    elif scan_result["nmap"]["scanstats"]["uphosts"] != "1" \
            and scan_result["nmap"]["scanstats"]["downhosts"] != "0":
        logger.info(current_time + " IP : %s  主机状态未知，请检查网络及其他相关情况" % scanned_target)
        return
    # tcp ports' condition and service
    warning_list = {}
    if "tcp" in scan_result["scan"][scanned_target].keys():
        tcp_port_list_in_scanned_result = scan_result["scan"][scanned_target]["tcp"].keys()
        for port in tcp_port_list_in_scanned_result:
            if scan_result["scan"][scanned_target]["tcp"][port]['state'] == "open":
                exist_flag = 0
                if security_sensitive_port_examination(port):
                    exist_flag = 1
                    warning_list[port] = scan_result["scan"][scanned_target]["tcp"][port]["product"]
                # logger.info("端口: %-6s\t 传输层协议: tcp\t 状态: %-7s\t 服务名: %s" % (port,
                #                                                             scan_result["scan"][scanned_target]
                #                                                             ["tcp"][port]['state'],
                #                                                             scan_result["scan"][scanned_target]
                #                                                             ["tcp"][port]["name"]
                #                                                             ))
                if (not exist_flag) \
                        and security_sensitive_service_examination(
                            scan_result["scan"][scanned_target]["tcp"][port]["product"]):
                    warning_list[port] = scan_result["scan"][scanned_target]["tcp"][port]["product"]

    needHandling = False

    if warning_list:
        needHandling = True
        for port, sensitive_service_item in warning_list.items():
            logger.info(current_time + " [Warning] IP: %s  发现敏感端口/协议，请处理: 端口:%-5s 协议:%s"
                        % (scanned_target, port, sensitive_service_item))
            warning_dict["info"].append([scanned_target, port, sensitive_service_item])

    if not needHandling:
        logger.info(current_time + " IP: %s  没有发现敏感端口与敏感协议" % scanned_target)
    return needHandling


# Parameter: ip_list, max_threads_num, tcp_ports, udp_ports
# Parameter Type: list, int, list, list
# Description: Finish the Tasks with MultiThreads, the Number of Threads can Be Set By The Config File,
#              somehow Like a ThreadPool
def scanned_task_producer(ip_list, max_threads_num, tcp_ports):
    print(ip_list)
    queue_object = Queue()
    for ip_item in ip_list:
        queue_object.put(ip_item)
    threads = [ScannedTaskConsumer(queue_object, single_ip_scan, tcp_ports)
               for _ in range(0, int(max_threads_num))]
    for t in threads:
        t.start()
    beginning_info = " 扫描开始时 线程数(含主线程): %d" % len(threading.enumerate())
    for t in threads:
        t.join()
        if t.exit_code != 0:
            print(t.exc_traceback)
            print(t.exception)
    return beginning_info


# Parameter: port
# Parameter Type: string
# Description: Warning if the Parameter "port" is a Sensitive One, Judging By the Sensitive Port List.
def security_sensitive_port_examination(port):
    flag = False
    if str(port) in sensitive_port_list:
        flag = True
    return flag


# Parameter: service_name
# Parameter Type: string
# Description: Warning if the Parameter "service_name" is a Sensitive One, Judging By the Sensitive Service List.
def security_sensitive_service_examination(service_name):
    flag = False
    # for sensitive_service_item in sensitive_service_list:
    #     if service_name.lower().search
    if service_name.lower() in sensitive_service_list:
        flag = True
    return flag


# Parameter: scan_start_time_log, scan_start_time_filename
# Parameter Type: string, string
# Description: Print Warning Messages Into the Log File For Log System, In Json
def write_json_warning_log_file(scan_start_time_log, scan_start_time_filename):
    warning_log_file_name = "./logs" + "/PortScan_M" + scan_start_time_filename + ".log"
    warning_dict["ScanTime"] = scan_start_time_log
    with open(warning_log_file_name, 'a+', encoding='utf-8') as f:
        json.dump(warning_dict, f)


if __name__ == "__main__":
    start_time = time.time()
    init_dir()
    threads_num_config, scan_list = read_config_from_ini_file(config_file)

    tcp_ports_to_scan = tcp_file_content_parser(read_port_list_from_file(tcp_port_list_file))
    scan_begin_time = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    threads_info_at_start = scanned_task_producer(scan_list, threads_num_config, tcp_ports_to_scan)

    # initialize the logger object
    currentTime = datetime.datetime.now().strftime("%Y-%m-%d=%H-%M-%S")
    normal_log_file_name = "./logs" + "/PortScan_P" + currentTime + ".log"
    logger = logging.getLogger("my_scanner_normal_info")
    logger.setLevel(level=logging.INFO)
    formatter = logging.Formatter("%(message)s")
    handler = logging.FileHandler(normal_log_file_name, encoding="utf-8")
    console = logging.StreamHandler()
    handler.setFormatter(formatter)
    console.setFormatter(formatter)
    logger.addHandler(handler)
    logger.addHandler(console)
    # beginning time of scanning, output info of threads
    logger.info(scan_begin_time + threads_info_at_start)
    # end time of scanning, output info of threads
    logger.info(datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S") +
                " 扫描结束时 线程数(含主线程): %d" % len(threading.enumerate()))

    warning_flag = False
    for target_ip in scan_list:
        if scan_result_output(target_ip, result_dist[target_ip]):
            warning_flag = True
    if warning_flag:
        write_json_warning_log_file(scan_begin_time, currentTime)
    end_time = time.time()
    time_cost = end_time - start_time
    logger.info("----------")
    logger.info("====================================================\n")
    logger.info(datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S") + " 完成, 本次任务总耗时: %f", time_cost)
