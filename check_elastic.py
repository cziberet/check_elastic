#!/usr/bin/env python
from datetime import datetime
from elasticsearch import Elasticsearch
import argparse
import json
from box import Box
import sys
import traceback

parser = argparse.ArgumentParser(
                    prog = 'check-elastic',
                    description = 'Query elastic metricbeat data for icinga checks')
parser.add_argument('-i', '--index', help='Index', default='metricbeat-*')
parser.add_argument('-t', '--time', help='time (5s,10m,1h,7d)', default='5m')
parser.add_argument('-m', '--metricset', help='metricset', required=True)
parser.add_argument('-f', '--metricfield', help='metricfield', nargs='+')
parser.add_argument('-H', '--host', help='hostname', required=True)
parser.add_argument('-e', '--elastic', help='elasticsearch host', default='101.0.0.25')
parser.add_argument('--protocol', help='elasticsearch protocol http/https', default='http')
parser.add_argument('-p', '--port', help='elasticsearch port', default='9200')
parser.add_argument('-w', '--warning', help='warning')
parser.add_argument('-c', '--critical', help='critical')
parser.add_argument('-cl', '--custom_level', help='critical', type=str, nargs='+')
parser.add_argument('-a', '--aggregation', help='aggregation methode (min,max,avg,sum,last)', type=str, default='avg',required=False)
parser.add_argument('-g', '--groupby', help='group by fieldname', type=str)
parser.add_argument('--alias', help='replace metricfield nem with an alias string', type=str)
parser.add_argument('--prefix', help='gives prefix to metricfileds name', type=str)
parser.add_argument('--filter', help='filter', type=str)

#custom_level warning/critical format: '{"field": field_name, "field_w": warning_value, "field_c": crit_value}'
#alias format: '{"fieldname": alias}'
#filter format: '{"op": "exclude", "fieldname": value}'

args = parser.parse_args()

es = Elasticsearch("{}://{}:{}".format(args.protocol,args.elastic,args.port), http_auth=('icinga','verysecurepassword'),verify_certs=False,ssl_show_warn=False)

def aggregate(data,aggr):
    if aggr=="avg":
        return sum(data)/len(data)
    if aggr=="min":
        return min(data)
    if aggr=="max":
        return max(data)
    if aggr=="sum":
        return sum(data)
    if aggr=="last":
        return data[-1]
    return None


def getValueByField(hit,metricfield):
    bucket=hit["_source"]
    for pathPoint in metricfield.split("."):
        bucket=bucket[pathPoint]
    return bucket

def filterHit(hit,metricFilter):
    try:
        filterData=json.loads(metricFilter)
    except:
        return True
    for key in filterData.keys():
        if key=="op":
            continue
        for filterValue in filterData[key].split("|"):
            if filterValue==getValueByField(hit,key):
                return True
    return False


def unitype(hits,metricfields,warning,critical,custom_level,aggr,alias,prefix,metricFilter):
    monitoringMessage=""
    monitoringExitCode=0
    try:
        filterData=json.loads(metricFilter)
    except:
        filterData=None
    if prefix is None:
        prefix=""
    try:
        tempDict={}
        for metricfieldpart in metricfields:
            for metricfield in metricfieldpart.split(","):
                tempList=[]
                for hit in hits:
                    try:
                        bucket=getValueByField(hit,metricfield)
                    except:
                        continue
                    if metricfield.split(".")[-1]=="pct":
                        bucket=float(bucket)*100
                    store=True
                    if filterData is not None and filterData["op"]=="exclude":
                        if filterHit(hit,metricFilter):
                            store=False
                    if filterData is not None and filterData["op"]=="include":
                        store=False
                        if filterHit(hit,metricFilter):
                            store=True
                    if store:
                        tempList.append(bucket)
                if len(tempList)>0:
                    tempDict[metricfield]=tempList
    except Exception as e:
        print("tempdict failure",e)
        traceback.print_exc()
        pass
    for metric in tempDict:
        warn=None
        crit=None
        if custom_level is not None:
            for cw in custom_level:
                try:
                    if json.loads(cw)["field"]==metric:
                        warn=float(json.loads(cw)["field_w"])
                except:
                    pass
                try:
                    if json.loads(cw)["field"]==metric:
                        crit=float(json.loads(cw)["field_c"])
                except:
                    pass
        if warn is None:
            warn=float(warning)
        if crit is None:
            crit=float(critical)

        if warn>crit:
            print("Warning value can not be greater than critical!")
            exit(3)
        metricValue=aggregate(tempDict[metric],aggr)
        tmpMsg=""
        metricStatus=0
        if float(metricValue)>=warn:
            metricStatus=1
        if float(metricValue)>=crit:
            metricStatus=2

        metricstatusText=""
        if metricStatus==0:
            metricStatusText="[OK]"
        elif metricStatus==1:
            metricStatusText="[WARNING]"
        elif metricStatus==2:
            metricStatusText="[CRITICAL]"
        else:
            metricStatus=3
            metricStatusText="[UNKNOWN]"

        if monitoringExitCode<metricStatus:
            monitoringExitCode=metricStatus
        unit=""
        if ".pct" in metric:
            unit="%"
        uom=""
#        if unit!="":
#            uom="["+unit+"]"
        try:
            aliases=json.loads(alias)
        except:
            pass
        try:
            metric=aliases[metric]
        except:
            pass
        monitoringMessage=monitoringMessage+"{} {}\t{} \t\t{:.4f} {}|{}={:.4f}{};{:.4f};{:.4f};;\n".format(metricStatusText,prefix, metric,metricValue,unit,metric,metricValue,unit,warn,crit)
        if "[" not in monitoringMessage:
            monitoringExitCode=3
    return {"message": monitoringMessage, "status": monitoringExitCode}

def grouptype(hits,metricfields,warning,critical,custom_level,aggr,groupby,metricFilter):
    monitoringMessage=""
    monitoringExitCode=0
    groups={}
    groups=set()
    dataGroups={}
    for hit in hits:
        bucket=hit["_source"]
        for pathPoint in groupby.split("."):
            bucket=bucket[pathPoint]
        groups.add(bucket)
    for group in groups:
        tempMetrics=[]
        for hit in hits:
            bucket=hit["_source"]
            for pathPoint in groupby.split("."):
                bucket=bucket[pathPoint]
            if bucket==group:
                tempMetrics.append(hit)
        dataGroups[group]=tempMetrics
    for dataPoint in dataGroups.keys():
        alias='{"system.filesystem.used.pct": "'+dataPoint+'"}'
        monitoringResult=unitype(dataGroups[dataPoint],metricfields,warning,critical,custom_level,aggr,alias,None,metricFilter)
        if len(monitoringResult["message"])>0:
            monitoringMessage=monitoringMessage+monitoringResult["message"]
        if monitoringResult["status"]>monitoringExitCode:
            monitoringExitCode=monitoringResult["status"]
    return {"message": monitoringMessage, "status": monitoringExitCode}

def monitoring(hits,metricfields,warning,critical,custom_level,aggr,groupby,alias,prefix,metricFilter):
    monitoringMessage=""
    monitoringExitCode=0
    if groupby is not None and len(groupby) > 1:
        monitoringResult=grouptype(hits,metricfields,warning,critical,custom_level,aggr,groupby,metricFilter)
        monitoringMessage=monitoringResult["message"]
        monitoringExitCode=monitoringResult["status"]
    else:
        monitoringResult=unitype(hits,metricfields,warning,critical,custom_level,aggr,alias,prefix,metricFilter)
        monitoringMessage=monitoringResult["message"]
        monitoringExitCode=monitoringResult["status"]

    print(monitoringMessage)
    exit(monitoringExitCode)

############################Elastic Query##################
#es_query = """
#{match_all: {
#    {"match_phrase": {"host.hostname": args.hostname}},
#    {"match_phrase": {"metricset.name": args.metricset}},
#    {"range":{"@timestamp":{"gte":("now-"+time),"lte":"now","format":"epoch_millis"}}}
#}}
#"""

searchQuery={
    "query": {
    "bool": {
      "must": [],
      "filter": [
        {
          "range": {
            "@timestamp": {
              "format": "strict_date_optional_time",
              "gte": ("now-"+args.time),
              "lte": "now"
            }
          }
        },
        {
          "match_phrase": {
            "metricset.name": args.metricset
          }
        },
        {
          "match_phrase": {
            "host.name": args.host
          }
        }
      ],
      "should": [],
      "must_not": []
    }
  }
}

#print(searchQuery)
#print(args.index)
resp = es.search(index=args.index, body=searchQuery,size='500')


#print("\n",resp)

#print("Got %d Hits:" % resp['hits']['total']['value'])
#for hit in resp['hits']['hits']:
#    print(hit)
if int(resp['hits']['total']['value']) == 0:
    print("No data found in elasticsearch!")
    exit(3)
if args.warning is not None and args.critical is not None and len(resp['hits']['hits']) > 0:
    monitoring(resp['hits']['hits'], args.metricfield, args.warning, args.critical, args.custom_level, args.aggregation, args.groupby,args.alias,args.prefix,args.filter)

print(resp['hits']['hits'])