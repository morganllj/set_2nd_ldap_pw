#!/bin/sh
#
# Morgan Jones (morgan@morganjones.org)

cmd_base=`basename $0`
cmd_base=`echo $cmd_base|sed 's/run_//'`
cmd_base=`echo $cmd_base|sed 's/\.sh//'`

dirname=`dirname $0`
p=`cd ${dirname} && pwd`;

cmd="${dirname}/${cmd_base}.pl -c ${dirname}/`basename ${p}`.cf $*"
echo $cmd
$cmd
