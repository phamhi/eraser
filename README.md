# eraser

Author: Hieu Pham
Date: December 2014
Version: <see VERSION>
Description: 

The purpose of this software is to delete or compress old logs. The retention 
period is set by GLOBAL_RET_DELETE and GLOBAL_RET_COMPRESS in the config.properties file.
New can be be defined after the GLOBAL definitions. The template for a new job is as follow:

#######################
## new job defintion ##
#######################
JOB_USER=<username>
. $RUN --execute-job
