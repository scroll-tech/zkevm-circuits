import pandas as pd, json, datetime, itertools
from sqlalchemy import create_engine, text
import warnings, time, os


warnings.simplefilter(action='ignore', category=FutureWarning)
warnings.simplefilter(action='ignore', category=UserWarning)
pd.options.mode.chained_assignment = None

def pgsql_engine(pgsqldb):
    '''
    creates a psql engine instance
    '''
    user     = pgsqldb['user']
    password = pgsqldb['password']
    host     = pgsqldb['host']
    database = pgsqldb['database']
    engine   = create_engine(f'postgresql://{user}:{password}@{host}:5432/{database}')

    return engine

def prepare_result_dataframe(test_result, sysstat,env, test_id):
    '''
    prepares postgres data (in the form of dataframe) for table circuit_benchmarks
    '''
    try:
        r = {
            'pull_request'          : test_result['pull_request'],
            'test_id'               : test_id,
            'circuit'               : test_result['circuit'],
            'degree'                : test_result['degree'],
            'test_result'           : test_result['result'],
            'test_date'             : datetime.datetime.now().date(),
            'setup_gen'             : test_result['setup_gen'],
            'proof_gen'             : test_result['proof_gen'],
            'proof_ver'             : test_result['proof_ver'],
            'max_ram'               : sysstat['max_ram'],
            'cpu_all_Average'       : sysstat['cpu_all_Average'],
            'cpu_all_Max'           : sysstat['cpu_all_Max'],
            'cpu_count'             : sysstat['cpu_count'],
            'sysstats_url'          : f'{env["grafana_dashboard_prefix"]}{test_id}',
            'logsurl'               : f'{env["s3endpoint"]}{test_id}.tar.gz'
        }

    except Exception as e:
        print(e)

    test_id = r['test_id']
    r = pd.DataFrame([r])
    r = r.set_index('test_date')
    
    return r

def write_mem_time(engine, mem_statistics, test_id, dummy=False):
    '''
    adds mem stats df as time series data to table mem_stats
    '''
    table = 'testresults_cbmemtime'
    mem_statistics['dummy'] = mem_statistics['timestamp'].apply(lambda x: f'{dummy}')
    mem_statistics['test_id'] = mem_statistics['timestamp'].apply(lambda x: f'{test_id}')
    mem_statistics.to_sql(table,engine,if_exists='append',index=False)

def write_cpuall_time(engine, cpu_statistics, test_id, dummy=False):
    '''
    adds cpu stats df as time series data to table mem_stats
    '''
    table = 'testresults_cbcpualltime'
    cpu_statistics['dummy'] = cpu_statistics['timestamp'].apply(lambda x: f'{dummy}')
    cpu_statistics['test_id'] = cpu_statistics['timestamp'].apply(lambda x: f'{test_id}')
    cpu_statistics.to_sql(table,engine,if_exists='append',index=False)

def calc_stats(cstats,mstats): 
    '''
    returns 2 dataframes with cpu/mem stats to be consumed by postgresql engine
    returns a dict with average/max cpu and max ram utilization durint the benchmark
    '''
    dfcpu,cpus = load_stats(cstats)
    cpustats,cpu_all_Max,cpu_all_Average = process_cpustats(dfcpu)
    dfmem, _ = load_stats(mstats)
    memstats,max_ram = process_memstats(dfmem)
    sysstat = {
        'cpu_all_Average': cpu_all_Average,
        'cpu_all_Max'    : cpu_all_Max,
        'cpu_count'      : cpus,
        'max_ram'        : f'{max_ram}Gb'
    }
    
    return cpustats, memstats, sysstat

def log_processor(pull_request,circuit, degree):
    '''
    Exports test metadata and result metrics from prover logfile
    '''
    SETUP_PREFIX     = "[Setup generation]"
    PROOFGEN_PREFIX  = "[Proof generation]"
    PROOFVER_PREFIX  = "[Proof verification]"
    logfile = [i for i in os.listdir('/home/ubuntu/') if 'proverlog' in i][0]
    f = open(f'/home/ubuntu/{logfile}', 'r')
    logdata = f.read()
    logdata = logdata.split("\n")
    running = [i for i in logdata if 'running' in i and 'test' in i][0].split()[1]
    if running != '0':
        r = [i.split(":")[1].split(".")[0].replace(" ","") for i in logdata if 'test result' in i][0]
        if r == 'ok':
            result = 'PASSED'
            try:
                sg = ''.join(g[0] for g in itertools.groupby([i for i in logdata if 'End' in i and SETUP_PREFIX in i ][0])).split('.', 1)[-1]
            except:
                sg = 'None'
            try:
                pg = ''.join(g[0] for g in itertools.groupby([i for i in logdata if 'End' in i and PROOFGEN_PREFIX in i ][0])).split('.', 1)[-1]
            except:
                pg = 'None'                
            try:
                pv = ''.join(g[0] for g in itertools.groupby([i for i in logdata if 'End' in i and PROOFVER_PREFIX in i ][0])).split('.', 1)[-1]
            except:
                pv = 'None'
            logdata = {
                    'pull_request': pull_request,
                    'circuit'     : circuit,
                    'degree'      : degree,
                    'result'      : result,
                    'setup_gen'   : sg,
                    'proof_gen'   : pg,
                    'proof_ver'   : pv
                }
        else:
            result = 'FAILED'
            logdata = {
                'pull_request': pull_request,
                'circuit'     : circuit,
                'degree'      : degree,
                'result'      : result,
                'setup_gen'   : 'None',
                'proof_gen'   : 'None',
                'proof_ver'   : 'None'
            }        

    else:
        result = 'None'
        logdata = {
            'pull_request': pull_request,
            'circuit'     : circuit,
            'degree'      : degree,
            'result'      : result,
            'setup_gen'   : 'NoTestExecuted',
            'proof_gen'   : 'NoTestExecuted',
            'proof_ver'   : 'NoTestExecuted'
            }

    
    return logdata

def load_stats(file):
    '''
    loads raw mem/cpu sar data from csv to dataframe
    '''
    try:
        with open(file,'r') as filedata:
            filedatalist = [i for i in filedata.read().splitlines()]
            header = [i for i in filedatalist if 'LINUX-RESTART' in i][0]
            cpus = header.split('(')[1].split()[0]
            cpudatalist = [i for i in filedatalist if 'LINUX-RESTART' not in i]
            columns = cpudatalist[0].split(';')
            cpudatalist = [i for i in cpudatalist if 'hostname' not in i]
            df = pd.DataFrame([i.split(';') for i in cpudatalist], columns=columns)
        return df, cpus
    except Exception as e:
        print(e)
        return None

def process_cpustats(statsdf):
    '''
    accepts cpu stats raw data from csv and returns a dataframe for further processing
    '''
    statsdf = statsdf[['timestamp', '%idle']]
    statsdf['%idle']   = pd.to_numeric(statsdf['%idle'])
    statsdf['utilizationall'] = statsdf['%idle'].apply(lambda x:round(float(100) - x, 2 ))
    statsdf = statsdf[['timestamp','utilizationall']]
    cpu_all_Max = statsdf['utilizationall'].max()
    cpu_all_Average = statsdf['utilizationall'].mean()
    return statsdf, cpu_all_Max,cpu_all_Average


def process_memstats(df):
    '''
    accepts ram stats raw data  and returns a dataframe for further processing
    '''
    statsdf = df[['timestamp', 'kbmemused']]
    statsdf['kbmemused']   = pd.to_numeric(statsdf['kbmemused'])
    statsdf['utilizationgb']   = statsdf['kbmemused'].apply(lambda x: round(x/float(1000000),2))
    statsdf = statsdf[['timestamp','utilizationgb']]
    max_ram = statsdf['utilizationgb'].max()
    return statsdf, max_ram
