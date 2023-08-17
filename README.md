# portScannerGadget
A Gadget For Scanning Sensitive Ports &amp; Services, on Linux default.
基于python3 & nmap完成的多线程敏感端口/服务扫描小工具

1.多线程实现，重写了threading库下run方法，队列+生产者消费者模型
2.需要nmap环境变量配置
3.配置文件说明：
  tcp_port_list.txt: 指定用于扫描的tcp端口，文件默认内容为0-65535即全端口扫描，如需更改请参考nmap中命令对端口参数的格式
  config.ini: 基本的配置信息：运行时最大线程数[max_threads]，所有IP[scan_targets]，敏感端口[sensitive_ports]，敏感服务[sensitive_services]
              config中除最大线程数外，其他字段中均为列表，请使用如“targets=1.2.3.4, 1.2.3.5, 1.2.3.6”格式。
4.支持多种日志格式：
  程序执行后会生成日志于目录logs下，记录日志时程序会自动检测该目录是否存在，不存在时会由程序自动创建，若已存在则不进行创建
  默认日志格式1:  PortScan_P + year-month-day + hour-minute-second
  默认日志格式2:  PortScan_M + year-month-day + hour-minute-second，机读日志中内容为json格式
