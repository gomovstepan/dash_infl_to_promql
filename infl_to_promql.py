#!/usr/bin/python3.6
# -*- coding: utf-8 -*-

#Перед использованием изменить таймренж




import requests
import json
import re
import pyparsing
import copy
import sqlparse
import urllib3
urllib3.disable_warnings()


headers_test = {
        'Accept': 'application/json',
        'Content-Type': 'application/json',
        'Authorization': '*****************'
    }



headers = {
        'Accept': 'application/json',
        'Content-Type': 'application/json',
        'Authorization': '***************************'
    }

proxies = {"http":"**********************************"}

grafana_headers = {'Authorization': '*************************************', headers=headers)
# reqs_name = reqs.json()


target_dts =  {
          "datasource": [],
          "exemplar": True,
          "expr": [],
          "interval": "",
          "legendFormat": [],
          "refId": [],
          "hide": []
        }

hidess = {
          "hide": []
}

dts = {
    'datasource': []
}

target_mixed = {
          "datasource": [],
          "exemplar": True,
          "expr": [],
          "interval": "",
          "legendFormat": [],
          "refId": [],
          "hide": []
        }

targets = []


def quantile_over_time(metric,param):
    quantile = ""
    for i in param:
        quantile = str(i)
    metric = f"quantile_over_time(0.{quantile}, {metric})"
    return metric

def non_negative_derivative(metric,param):
    for i in param:
        if len(i) > 0:
            time = str(i).replace("'","")
            metric = f"keep_last_value(idelta({metric})[{time}] >= 0)"
        else:
            metric = f"keep_last_value(idelta({metric}) >= 0)"
        return metric

def non_negative_difference(metric,param):
    time = ""
    time = time.join(param).replace("'","")
    if time != "":
        metric = f"increase({metric}[{time}])"
    else:
        metric = f"increase({metric})"
    return metric

def difference(metric,param):
    time = ""
    time = time.join(param).replace("'","")
    if time != "":
        metric = f"increase({metric}[{time}])"
    else:
        metric = f"increase({metric})"
    return metric

def math(metric,param):
    digit = ""
    digit = digit.join(param)
    if digit != "":
        metric = metric + digit
    return metric



def OR_replace(tag):
    counter = 0
    hashs = ""
    for pis in tag.split('"'):
        if counter == 0:
            hashs = pis + ' "'
        if counter%2 != 0:
            hashs += pis + "|"
        counter +=1
    i = hashs[:-1] + '"'
    return(i)


def prmql_query(query):
    query = query.replace('"ret_30w".',"").split("GROUP BY")[0].split("group by")[0].split('AND $timeFilter')[0].replace('$timeFilter and',"").replace('$timeFilter AND',"").replace('$timeFilter',"")
    metric = ""
    try:
        parsed = sqlparse.parse(query)[0]
        parsed1 = sqlparse.parse(query)
        query = query.replace("from","FROM").replace("where","WHERE")
        mes = query.split("FROM")[1].split("WHERE")[0]
        mes = mes.replace('"','').replace('(','').replace(')','').replace(' ','')
        tag = query.split("WHERE")[1].replace('"','').replace("'",'"').replace('and',',').replace('AND',',').replace("|", ".*|.*").replace('st,','stand').replace('\\','')
        tag = "{" + tag + "}"
        field = query.split('FROM')[0].split('from')[0].replace("SELECT","").replace("select","").replace("non_negative_derivative(","idelta(").replace("non_negative_difference(","increase(").replace("difference(","idelta(").replace("sum(","sum_over_time(").replace("min(","min_over_time(").replace("max(","max_over_time(").replace("mean(","avg_over_time(").replace("derivative(","deriv(")
        field1 = ""
        if re.search("AS",field) or re.search(" as",field):
            if re.search("AS",field):
                cnt = 0
                for fld in field.split('AS'):
                    if cnt == 0:
                        field1 = fld
                    if re.search(',',fld):
                        if cnt != 0:
                            field1 += "," + fld.split(',')[1]
                    cnt += 1
            if re.search(" as",field):
                cnt = 0
                for fld in field.split('as'):
                    if cnt == 0:
                        field1 = fld
                    if re.search(',',fld):
                        if cnt != 0:
                            if re.search('"',fld):
                                field1 = fld.split('"')[1].split('"')[0]
                            else:
                                field1 += "," + fld.split(',')[1]
                    cnt += 1
        elif re.search("percentile",field):
            field = field.replace('percentile','').replace('(','').replace(')','').replace('"','')
            field = '(0.' + field.split(',')[1].replace(' ', '') + ',' + field.split(',')[0] + ')'
        if field1 != "":
            field = field1
        tag2 = ""
        for i in tag.split(','):
            flag = False
            if re.search("host",i) or re.search("name",i) or re.search("key_group",i) or re.search("status",i) or re.search("ora_instance",i) or re.search("errorClass",i) or re.search("flowName",i):
                if re.search("= ",i) or re.search('="',i) or re.search('=  ',i):
                    counter = 0
                    tagot = ""
                    i = i.replace('=','=~ ')
                    for k in i.split('"'):
                        counter +=1
                        if counter%2 == 0:
                            k = '"' + k + '.*"'
                        tagot += k
                    if re.search("OR",tagot) or re.search("or",tagot):
                        flag = True
                        tagot = OR_replace(tagot)
                    tag2 += tagot + ","
                else:
                    counter = 0
                    for k in i.split("/"):
                        counter +=1
                        if counter%2 == 0:
                            k = '".*' + k + '.*"'
                        tag2 += k
                    tag2 += ","
                    if re.search("OR",tag2) or re.search("or",tag2):
                        flag = True
                        tagot = OR_replace(tag2)
                        tag2 = tagot + ","
                flag = True
            if  re.search("\$",i):
                i = i.replace("/^",'"').replace('$/','"').replace('/$','".*$').replace('/','.*"')
                if re.search("OR",i) or re.search("or",i):
                    flag = True
                    i = OR_replace(i)
                    tag2 += i + ","
            if flag == False:
                if re.search("OR",i) or re.search("or",i):
                    flag = True
                    i = OR_replace(i) + '"'
                    tag2 += i + ","
                else:
                    tag2 += i + ","
        tag2 = tag2[:-1] + "}"
        if not re.search("\(",field):
            field = '" ' + field.replace('"','').replace(" ","") + '"'
            metric = field.replace('" ',f'{mes}_').replace('"', f'{tag2}')
        else:
            if re.search('"\)',field):
                metric = field.replace('("',f'({mes}_').replace('")', f'{tag2})')
            else:
                metric = field.replace('"','').replace('(',f'({mes}_').replace(')', f'{tag2})')
        metric = agregation(metric)
    except:
        metric = False
    return metric

def agregation(metric):
    metric = metric.replace("last(","(").replace(".*.*", ".*").replace('""', '"').replace('  ', ' ').replace("~~", "~").replace("{  ,","{").replace("{ ,","{").replace("{,","{").replace("}}","}").replace('{ (','{ ').replace(') }',' }').replace('.*.-','.*-').replace('..','.').replace('/.','".*').replace('./','.*"').replace("percentile","quantile_over_time").replace('^','').replace('$.*','.*').replace('<>','!=').replace(' (','').replace(') ','')
    return metric




def check_queries(metric, target, datasource):
    influxql_metric = ""
    promql_metric = metric
    promql_metric = promql_metric.replace("{","%7B").replace("}","%7D").replace('"','%22').replace("=","%3D").replace(",","%2C").replace("/","%2F").replace("|","%7C").replace("[","%5B").replace("]","%5D").replace(" ","%20").replace("'","%27")
    promql_metric = promql_metric 
    if 'measurement' in target:
        mes = target['measurement']
        if 'select' in target:
            for select in target['select']:
                for param in select:
                    if 'params' in param and 'type' in param:
                        if param['type'] == "field":
                            for i in param['params']:
                                field = i
                            select = f'SELECT last("{i}") FROM "{mes}" WHERE ('
                            for tag in target['tags']:
                                if 'condition' in tag:
                                    condition = tag['condition']
                                    key = tag['key']
                                    operator = tag['operator']
                                    value = tag['value']
                                    if value[0] == "/" and value[-1] == "/":
                                        select += f' {condition} "{key}" {operator} {value}'
                                    else:
                                        select += f' {condition} "{key}" {operator} %27{value}%27'
                                else:
                                    key = tag['key']
                                    operator = tag['operator']
                                    value = tag['value']
                                    if value[0] == "/" and value[-1] == "/":
                                        select += f'"{key}" {operator} {value}'
                                    else:
                                        select += f'"{key}" {operator} %27{value}%27'
                            select += ")%20AND%20time%20%3E%3D%20now()%20-%206h%20GROUP BY time(1m) fill(none)"
                            influxql_metric = select.replace("{","%7B").replace("}","%7D").replace('"','%22').replace("=","%3D").replace(",","%2C").replace("/","%2F").replace("|","%7C").replace("[","%5B").replace("]","%5D").replace(" ","%20").replace("'","%27")
    else:
        select = target + ")%20AND%20time%20%3E%3D%20now()%20-%206h%20GROUP BY time(1m) fill(none)"
        influxql_metric = select.replace("{","%7B").replace("}","%7D").replace('"','%22').replace("=","%3D").replace(",","%2C").replace("/","%2F").replace("|","%7C").replace("[","%5B").replace("]","%5D").replace(" ","%20").replace("'","%27")
    promql_data = True
    influxql_data = True
    if datasource == "InfluxDB_bank2 (telegraf)" or datasource == "InfluxDB_bank4 (telegraf)" or datasource == "InfluxDB_bank4(telegraf)" or datasource == "InfluxDB_bank5 (telegraf)":
        promql_request = requests.get(f"https://grafana.megafon.ru/api/datasources/proxy/891/api/v1/query_range?query={promql_metric}", headers = headers, proxies = proxies)
        influxql_request = requests.get(f"https://grafana.megafon.ru/api/datasources/proxy/459/query?db=telegraf&q={influxql_metric}", headers = headers, proxies = proxies)
        promql_request = json.loads(promql_request.content)
        influxql_request = json.loads(influxql_request.content)
        try:
            if len(promql_request['data']['result']) == 0:
                promql_data = False
        except:
            promql_data = False
        try:
            for i in influxql_request['results']:
                if 'series' in i:
                    influxql_data = True
                else:
                    influxql_data = False
        except:
            influxql_data = False
    if datasource == "InfluxDB_bank3 (mondb)" or datasource == "InfluxDB_bank4 (mondb)":
        promql_request = requests.get(f"https://grafana.megafon.ru/api/datasources/proxy/892/api/v1/query_range?query={promql_metric}", headers = headers, proxies = proxies)
        influxql_request = requests.get(f"https://grafana.megafon.ru/api/datasources/proxy/277/query?db=mondb&q={influxql_metric}", headers = headers, proxies = proxies)
        promql_request = json.loads(promql_request.content)
        influxql_request = json.loads(influxql_request.content)
        try:
            if len(promql_request['data']['result']) == 0:
                promql_data = False
        except:
            promql_data = False
        try:
            for i in influxql_request['results']:
                if 'series' in i:
                    influxql_data = True
                else:
                    influxql_data = False
        except:
            influxql_data = False
    to_change = True
    alert = False
    if promql_data == False and influxql_data == True:
        to_change = False
        alert = True
    if promql_data == False and influxql_data == False:
        alert = True
    return to_change, alert





def gen_metric(target, datasource):
    metric = ""
    alert = True
    to_change = False
    counter = 0
    if 'measurement' in target:
        if 'select' in target:
            for select in target['select']:
                for param in select:
                    if 'params' in param and 'type' in param:
                        if param['type'] == "field":
                            for i in param['params']:
                                counter += 1
                                metric = target['measurement'] + "_" + i
                                if 'tags' in target:
                                    if target['tags'] != []:
                                        metric += "{"
                                        for tag in target['tags']:
                                            if 'condition' in tag and tag['condition'] == "OR":
                                                var = tag['key'] + '="'
                                                var1 = tag['key'] + '=~"'
                                                metric = metric.replace(var,var1)
                                                metric = metric[:-2] + "|"
                                                if tag['key'] == "host":
                                                    if tag['operator'] == "=" or tag['operator'] == "!=":
                                                        metric +=  tag['value'] +'.*"'+ ","
                                                    elif tag['operator'] == "=~" or tag['operator'] == "!~":
                                                        metric +=  tag['value'].replace("/", ".*")  +'"'+ ","
                                                elif tag['key'] != "path" and tag['key'] != "api" and tag['key'] != "uri" and tag['key'] != "directory":
                                                    metric += tag['value'].replace("/", ".*")  +'"'+ ","
                                                elif tag['key'] == "path" or tag['key'] == "api" or tag['key'] == "uri" or tag['key'] == "directory":
                                                    if tag['operator'] == "=" or tag['operator'] == "!=":
                                                        metric += tag['value']  +'"'+ ","
                                                    elif tag['operator'] == "=~" or tag['operator'] == "!~":
                                                        val = tag['value'][:-1]
                                                        metric += '.*' + val  +'.*"'+ ","
                                                else:
                                                    metric += tag['value']  +'"'+ ","
                                            elif tag['key'] == "host" and tag['operator'] == "=":
                                                metric += tag['key'] + tag['operator']+ "~" + '"' + tag['value'].replace("/", ".*")  +'.*"'+ ","
                                            elif tag['key'] == "host" and tag['operator'] == "=~":
                                                metric += tag['key'] + tag['operator'] + '"' + tag['value'].replace("/", ".*")  +'.*"'+ ","
                                            elif tag['key'] != "path" and tag['key'] != "api" and tag['key'] != "uri" and tag['key'] != "directory":
                                                metric += tag['key'] + tag['operator'] + '"' + tag['value'].replace("/", ".*")  +'"'+ ","
                                            elif tag['key'] == "api" or tag['key'] == "uri":
                                                if tag['operator'] == "=" or tag['operator'] == "!=":
                                                    metric += tag['key'] + tag['operator'] + '"' + tag['value']  +'"'+ ","
                                                elif tag['operator'] == "=~" or tag['operator'] == "!~":
                                                    val = tag['value'][:-1]
                                                    metric += tag['key'] + tag['operator'] + '".*' + val  +'.*"'+ ","
                                            elif tag['key'] == "directory" or tag['key'] == "path":
                                                if tag['operator'] == "=" or tag['operator'] == "!=":
                                                    metric += tag['key'] + tag['operator'] + '"' + tag['value']  +'"'+ ","
                                                elif tag['operator'] == "=~" or tag['operator'] == "!~":
                                                    val = tag['value']
                                                    if re.search("\/.\*", val) and re.search(".\*\/", val):
                                                        val = val.replace(".*/",'.*"').replace("/.*",'".*').replace(".*/",'.*"')
                                                        val = val.replace('\\', '')
                                                        metric += tag['key'] + tag['operator'] + val + ","
                                                    else:
                                                        val = val.replace('\\', '')
                                                        metric += tag['key'] + tag['operator'] + '".*' + val  +'.*"'+ ","
                                                    metric = metric.replace('$','')
                                            else:
                                                metric += tag['key'] + tag['operator'] + '"' + tag['value']  +'"' + ","
                                        metric = metric[:-1] + "}"
                                        metric = metric.replace("*.*.*", ".*").replace(".*.*", ".*").replace('".*/.*/','".*/').replace('".*/.*','".*/')
                                        if re.search("\$", metric):
                                            metric = metric.replace("$.*",".*").replace("^$","$")
                                            to_change = True
                                            alert = False
                                        else:
                                            to_change, alert = check_queries(metric, target, datasource)
                    if metric != "":
                        if re.match(param['type'],"non_negative_derivative"):
                            metric = non_negative_derivative(metric,param['params'])
                        if re.match(param['type'],"non_negative_difference"):
                            metric = non_negative_difference(metric,param['params'])
                        if re.match(param['type'],"percentile"):
                            metric = quantile_over_time(metric,param['params'])
                        if param['type'] == "math":
                            metric = math(metric,param['params'])
                        if param['type'] == "difference":
                            metric = f"idelta({metric})"
                        if param['type'] == "sum":
                            metric = f"sum_over_time({metric})"
                        if param['type'] == "min":
                            metric = f"min_over_time({metric})"
                        if param['type'] == "max":
                            metric = f"max_over_time({metric})"
                        if param['type'] == "mean":
                            metric = f"avg_over_time({metric})[1m]"
                        if param['type'] == "count":
                            metric = f"count({metric})"
                        if param['type'] == "derivative":
                            metric = f"deriv({metric})"
            if counter > 1:
                to_change = False
                alert = True
            return metric, to_change, alert

def gen_snmp_metric(target):
    if 'measurement' in target:
        if target['measurement'] == "sysmonProcCpuTable":
            tags = json.loads(json.dumps(target['tags']))
            metric = "cpu_usage_active{"
            for i in target['tags']:
                tags = json.loads(json.dumps(i))
                metric += tags['key'] + tags['operator'] + '"' + tags['value'].replace('.',"").replace('*',"") + '.*",'
            metric = metric.replace("/","") + 'cpu="cpu-total"}'
            return metric
        elif target['measurement'] == "sysmonDiskTable":
            tags = json.loads(json.dumps(target['tags']))
            metric = "disk_used_percent{"
            for i in target['tags']:
                tags = json.loads(json.dumps(i))
                if tags['key'] == "host":
                    metric += tags['key'] + tags['operator'] + '"' + tags['value'].replace('.',"").replace('*',"").replace("/","") + '.*",'
                elif tags['key'] == "sysmonDiskPath":
                    metric += "path" + tags['operator'] + '"' + tags['value'].replace('.',"").replace('*',"") + '",'
            metric = metric[:-1].replace("","") + '}'
            return metric
        elif target['measurement'] == "sysmonProcStateTable":
            tags = json.loads(json.dumps(target['tags']))
            metric = "procstat_lookup_running{"
            for i in target['tags']:
                tags = json.loads(json.dumps(i))
                if tags['key'] == "host":
                    metric += tags['key'] + tags['operator'] + '"' + tags['value'].replace('.',"").replace('*',"").replace("/","") + '.*",'
                elif tags['key'] == "sysmonDiskPath":
                    metric += "path" + tags['operator'] + '"' + tags['value'].replace('.',"").replace('*',"") + '",'
            metric = metric[:-1].replace("","") + '}'
            return metric
        else:
            return 404
    else:
        return 404

def check_row(target,datasource):
    changes = True
    metric = ""
    if 'rawQuery' in target:
        if target['rawQuery'] == False:
            try:
                metric, changes, alert = gen_metric(target, datasource)
            except:
                changes = False
                alert = True
        else:
            query = target['query']
            metric = prmql_query(query)
            to_change, alert = check_queries(metric, query, datasource)
    else:
        try:
            metric, changes, alert = gen_metric(target, datasource)
        except:
            changes = False
            alert = True
    return metric, changes, alert




def if_targets(panel,mixed):
    targets = []
    alert = False
    if mixed == False:
        if 'datasource' in panel:
            if panel['datasource'] == "InfluxDB_bank2 (telegraf)" or panel['datasource'] == "InfluxDB_bank4 (telegraf)" or panel['datasource'] == "InfluxDB_bank4(telegraf)" or panel['datasource'] == "InfluxDB_bank5 (telegraf)" or panel['datasource'] == "InfluxDB_bank3 (mondb)" or panel['datasource'] == "InfluxDB_bank4 (mondb)":# or panel['datasource'] == "InfluxDB_bank3 (snmp_int)" or panel['datasource'] == "InfluxDB_bank4 (snmp_int)":
                datasource = panel['datasource']
                for target in panel['targets']:
                    metric = ""
                    targ_alias = False
                    alias = """host: {{host}} appl_id: {{appl_id}} app: {{application}} Статус:"""
                    hide = ""
                    if 'hide' in target:
                        hide = target['hide']
                    else:
                        hide = False
                    if 'refId' in target:
                        refId = target['refId']
                    else:
                        refId = 'A'
                    if 'groupBy' in target:
                        for params in target['groupBy']:
                            param = json.loads(json.dumps(params))
                            if param['type'] == "tag":
                                for tag in param['params']:
                                    alias += "{{" + tag + "}} "
                    # if alias == "":
                    #     if 'alias' in target:
                    #         aliases = target['alias']
                    #         if re.match("$tag_", aliases):
                    #             aliases = aliases.replace("$tag_","{{")
                    #             for tag in aliases.split(' '):
                    #                 if tag != "-" and tag != "--":
                    #                     targ_alias == True
                    #                     alias += tag + "}} - "
                    #         else:
                    #             alias = aliases
                    if targ_alias == True:
                        alias = alias[:-2]
                    metric, changes, alert_ref = check_row(target, datasource)
                    if alert_ref == True:
                        alert = True
                    if changes == True:
                        target = copy.deepcopy(target_dts)
                        if panel['datasource'] == "InfluxDB_bank2 (telegraf)" or panel['datasource'] == "InfluxDB_bank4 (telegraf)" or panel['datasource'] == "InfluxDB_bank4(telegraf)" or panel['datasource'] == "InfluxDB_bank5 (telegraf)":
                            target['datasource'] = "Prometheus (prod)"
                        if panel['datasource'] == "InfluxDB_bank3 (mondb)" or panel['datasource'] == "InfluxDB_bank4 (mondb)":
                            target['datasource'] = "Prometheus (others)"
                        target['expr'] = metric
                        target['legendFormat'] = alias
                        target['refId'] = refId
                        if hide != "":
                            target['hide'] = hide
                        else:
                            target['hide'] = False
                        targets.append(target)
                    else:
                        if panel['datasource'] == "InfluxDB_bank2 (telegraf)" or panel['datasource'] == "InfluxDB_bank4 (telegraf)" or panel['datasource'] == "InfluxDB_bank4(telegraf)" or panel['datasource'] == "InfluxDB_bank5 (telegraf)":
                            target['datasource'] = "InfluxDB_bank2 (telegraf)"
                        if panel['datasource'] == "InfluxDB_bank3 (mondb)" or panel['datasource'] == "InfluxDB_bank4 (mondb)":
                            target['datasource'] = "InfluxDB_bank3 (mondb)"
                        targets.append(target)
    else:
        for target in panel['targets']:
            targ_alias = False
            alias = """host: {{host}} appl_id: {{appl_id}} app: {{application}} Статус:"""
            hide = ""
            if 'hide' in target:
                hide = target['hide']
            refId = target['refId']
            if 'groupBy' in target:
                for params in target['groupBy']:
                    param = json.loads(json.dumps(params))
                    if param['type'] == "tag":
                        for tag in param['params']:
                            alias += "{{" + tag + "}} "
            # if alias == "":
            #     if 'alias' in target:
            #         aliases = target['alias']
            #         if re.match("$tag_", aliases):
            #             aliases = aliases.replace("$tag_","{{")
            #             for tag in aliases.split(' '):
            #                 if tag != "-" and tag != "--":
            #                     targ_alias == True
            #                     alias += tag + "}} - "
            #         else:
            #             alias = aliases
            if targ_alias == True:
                alias = alias[:-2]
            if 'datasource' in target:
                if target['datasource'] == "InfluxDB_bank2 (telegraf)" or target['datasource'] == "InfluxDB_bank4 (telegraf)" or target['datasource'] == "InfluxDB_bank4(telegraf)" or target['datasource'] == "InfluxDB_bank5 (telegraf)":
                    datasource = target['datasource']
                    metric, changes, alert_ref = check_row(target, datasource)
                    if alert_ref == True:
                        alert = True
                    if changes == False:
                        targets.append(target)
                        continue
                    else:
                        target = copy.deepcopy(target_dts)
                        target['datasource'] = "Prometheus (prod)"
                        target['expr'] = metric
                        target['legendFormat'] = alias
                        target['refId'] = refId
                        if hide != "":
                            target['hide'] = hide
                        else:
                            target['hide'] = False
                if target['datasource'] == "InfluxDB_bank3 (mondb)" or target['datasource'] == "InfluxDB_bank4 (mondb)":
                    datasource = target['datasource']
                    metric, changes, alert_ref = check_row(target, datasource)
                    if alert_ref == True:
                        alert = True
                    if changes == False:
                        targets.append(target)
                        continue
                    else:
                        target = copy.deepcopy(target_dts)
                        target['expr'] = metric
                        target['datasource'] = "Prometheus (others)"
                        target['legendFormat'] = alias
                        target['refId'] = refId
                        if hide != "":
                            target['hide'] = hide
                        else:
                            target['hide'] = False
            targets.append(target)
    return targets, alert


def panel_convert(panel, panels_id):
    panel_id = panel['id']
    if 'datasource' in panel:
        if panel['datasource'] == "-- Mixed --":
            mixed = True
            if 'targets' in panel:
                targets, alert = if_targets(panel,mixed)
                if alert == True:
                    panels_id.append(panel_id)
                if targets != []:
                    panel['targets'] = targets
        elif 'targets' in panel:
            mixed = False
            targets, alert = if_targets(panel,mixed)
            if alert == True:
                panels_id.append(panel_id)
            if targets != []:
                datasources = []
                for target in targets:
                    if 'datasource' in target:
                        dts = str(target['datasource'])
                        datasources.append(dts)
                datasources = set(datasources)

                if len(datasources) == 1:
                    try:
                        for target in targets:
                            if 'datasource' in target:
                                del target['datasource']
                        for i in datasources:
                            panel['datasource'] = i
                    except:
                        pass
                else:
                    panel['datasource'] = '-- Mixed --'
                panel['targets'] = targets
    return panel, panels_id



req = ['60hTd2QWk']

for uid in req:
    panels_id = []
    reqs = requests.get(f'https://grafana.megafon.ru/api/dashboards/uid/{uid}', headers=headers)
    reqs_name = reqs.json()
    ssilki = []
    if 'dashboard' in reqs_name:
        if 'panels' in reqs_name['dashboard']:
            for panels in reqs_name['dashboard']['panels']:
                if 'type' in panels and 'panels' in panels and panels['type'] == "row":
                    for panel in panels['panels']:
                        convert_panel, panels_id = panel_convert(panel, panels_id)
                        panel = convert_panel
                else:
                    convert_panel,panels_id = panel_convert(panels, panels_id)
                    panels = convert_panel
            name_dash = reqs_name['dashboard']['title']
            # reqs_name['dashboard']['uid'] = None
            # reqs_name['dashboard']['id'] = None
            reqs_name['dashboard']['gnetId'] = None
            reqs_name['dashboard']['editable'] = True
            # reqs_name['folderId'] = 8254
            # reqs_name['folderUid'] = 'w3UQMeDnk'
            reqs_name['dashboard']['overwrite'] = True
            name_dash = reqs_name['dashboard']['title']

            dashboard = copy.deepcopy(reqs_name)
            data = json.dumps((dashboard), indent=2)
            req = requests.post('https://grafana.megafon.ru/api/dashboards/db', headers=headers, data=data, verify=False)
            req = req.json()
            if 'importedUrl' in req:
                importedUrl = req['importedUrl']
                dash = f"https://grafana.megafon.ru{importedUrl}"
                ssilki.append(dash)
                for ids in panels_id:
                    ssilka = f"https://grafana.megafon.ru{importedUrl}?orgId=1&editPanel={ids}"
                    ssilki.append(ssilka)
            elif 'message' in req:
                ssilki.append(req['message'])
                print(ssilki)
            else:
                print(req)
        else:
            print("Baaaaad dash")
    for i in ssilki:
        print(i)

#  {'id': 8254, 'uid': 'w3UQMeDnk', 'title': 'Converted Dashes'}
