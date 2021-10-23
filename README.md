# Research goal
Detecting potential sniffers on Linux machines

# Intro
The methods presented in this study can be used to detect sniffers on Linux systems. </br>
Attackers may leverage access to the machine and sniff the network in order to capture information about an environment, including authentication material passed over the network. </br>
Most sniffers use RAW sockets (requires root permissions) instead of Datagram/Streaming sockets, since raw sockets enable direct access to lower-level protocols. </br>
The research focused on tcpdump and tshark, two of the common network sniffing tools, but other tools using similar techniques should also be able to be detected. </br>
</br>
![alt text](https://github.com/0x0ranm/SnifferDetector/blob/main/img6.JPG?raw=true)

# Method1 - raw socket usage
</br>
As previously mentioned, most processes in the system do not use a RAW socket.</br>
Using this information, the first detection method will identify processes that are using RAW sockets.</br>
In this example, I will use the lsof command, which displays open files by process on a linux system.</br></br>

![alt text](https://github.com/0x0ranm/SnifferDetector/blob/main/img2.JPG?raw=true)
<p align="center">processes with open RAW sockets</p>

# Method 2 - Specific Libraries usage</br>

While searching for sniffers on a machine, running processes that use those libraries will also be identified as potential sniffers.</br>
1.libpcap</br>
2.libwireshark</br></br>
![alt text](https://github.com/0x0ranm/SnifferDetector/blob/main/img4.JPG?raw=true)
<p align="center">tshark loaded shared libraries</p>
<p >
  <img src="https://github.com/0x0ranm/SnifferDetector/blob/main/img3.JPG">
</p>
<p align="center">tcpdump loaded shared libraries</p>
</br>
<h1>Proof of concept</h1>

The POC searches for processes that are using at least one of the described methods and returns information about the process.
<p >
  <img src="https://github.com/0x0ranm/SnifferDetector/blob/main/img5.JPG">
</p>
<p align="center">POC usage example</p>
