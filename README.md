# DetectInconsistencies
The Final Aim is to Detect the Inconsistencies in Public Security Vulnerability Reports.
So far,the program can craw some public security vulnerablility information. 

# Dependence
    Python >=3.6
# User Guide
If you're in China,you need cross the Great Wall in order to make the program(craw_report.py) craw some websites(e.g. arch/info website).I use shadowsocks to run the program.Use `proxychains` to force the program run with the proxy in linux or use shadowsocks with "全局模式" in windows.

## linux
If you need to cross the wall in linux,run the program like this:+

    proxychains python entry.py

If you don't need to cross the wall in linux,you can run the program like this:  
    
    python entry.py

## windows
 Run the program in windows with(if you need cross the wall,use shadowsocks with "全局模式"):
    python entry.py 