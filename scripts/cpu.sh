#!/bin/bash
cat /proc_host/loadavg | awk '{printf "Current CPU Utilization is ";print $1;}'