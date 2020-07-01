# http_hw_4

Сервер работает в несколько потоков. 

Отчёт о проведении нагрузочного тестирования с помощью Apache Benchmark:

Server Software:        example.local

Server Hostname:        localhost

Server Port:            80


Document Path:          /

Document Length:        9 bytes

Concurrency Level:      100

Time taken for tests:   37.632 seconds

Complete requests:      50000

Failed requests:        0

Non-2xx responses:      50000

Total transferred:      3850000 bytes

HTML transferred:       450000 bytes

Requests per second:    1328.66 [#/sec] (mean)

Time per request:       75.264 [ms] (mean)

Time per request:       0.753 [ms] (mean, across all concurrent requests)

Transfer rate:          99.91 [Kbytes/sec] received


Connection Times (ms)

              min  mean[+/-sd] median   max

Connect:        0    0   0.4      0       2

Processing:    19   71   8.6     66     112

Waiting:       15   71   8.6     66     112

Total:         19   71   8.6     66     112


Percentage of the requests served within a certain time (ms)

  50%     66
  
  66%     70
  
  75%     77
  
  80%     78
  
  90%     87
  
  95%     89
  
  98%     91
  
  99%     94
 
 100%    112 (longest request)
