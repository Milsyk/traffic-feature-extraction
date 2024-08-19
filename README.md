# traffic-feature-extraction
流量特征提取
使用PYthon 截取网卡流量，并提取数据包中TCP层的Windows Options，Payload等参数，输出结果保存在url_feature.bcp文件

foreigndomains文件是读取的网站信息

1.url_get_tezheng-20240528.py截取网卡某个网络端口的数据

2.url_get_tezheng-AndroidIPhone.py通过Android连接，调用命令的方式访问浏览器截取数据

3.url_get_tezheng-pcpaTobcp.py通过对pcap文件的处理，生成结果

4.url_get_tezheng-selenimu.py调用Chrome内核的方式访问浏览器，截取产生的数据，输出相关的结果
