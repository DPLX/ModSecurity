


ModSecurity False Positive Detector
===================================

With the help of this script it is possible to detect ModSecurity False Positive. Therefore you can filter a given log for different arguments.
For further informations see the upcoming parameters and exmples

required parameters:
--------------------
-o   Specification of the output. Options console or file
     exmaple: ... -o console ...
     exmaple: ... -o file=exceptions.txt ...
-l   Specification of the input file.
     example: ... -l logs/project_x.log

additional filter parameters:
----------------------
-r   Filter via remote address
     example: ... -r 192.168.2.1
-u   Filter via user-agent
     example: ... -u firefox
-t   Filter via timestamp or a timestamp. Specification in the unix-timestamp format
     example: ... -t 12345- (start = timestamp x, end = not defined
     example: ... -t -12345 (start = not defined, end = timestamp x)
     example: ... -t 12345-54321 (start = timestamp x, end = timestamp y)
-q   Ex- or include querystrings. Default: exclude querystrings
     example: ... -q false (excludes querystrings)
     example: ... -q true (includes querystrings)
-m   Ex- or include media files. Default: exclude media files
     example: ... -m false (excludes media files)
     example: ... -m true (inlcudes media files)
-p   Specify a path
     example: ... -p /path/to/nowhere
-r   exclude rules
     example: ... -r 12345 (excludes one rule)
     example: ... -r '(12345|54321)' (excludes more rules)
-e   exclude path
     example: ... -e string (excludes one path)
     example: ... -e '(string1|string2|string3)' (excludes multiple pathes)
-s   exclude http-status
-c   define modsecurity ruleset categorie

Example:
--------
falsepositive_analyse.py -r 192.168.2.1 -u firefox -t 1234534354-3466238468 -q false -m false -p /home/ -r '(12345|23412)'
