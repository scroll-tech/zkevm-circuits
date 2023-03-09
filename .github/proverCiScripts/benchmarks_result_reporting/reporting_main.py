import argparse, json
from pprint import pprint
import reporting_modules as rmod

env = json.load(open('/home/CI/env.json'))
cstats = '/home/CI/cpu.stats'
mstats = '/home/CI/mem.stats'

def main():
    parser = argparse.ArgumentParser(
                    prog = 'BenchmarkResults',
                    usage = 'python3 reporting_main.py 13 EVM 19',
                    description = 'Writes circuit benchmark results to postgresql, uploads logfiles to s3 bucket',
                    )
    parser.add_argument('pr') 
    parser.add_argument('circuit')
    parser.add_argument('degree')
    parser.add_argument('test_id')
    args = parser.parse_args()
    pr, circuit, degree, test_id = (args.pr, args.circuit, args.degree, args.test_id)
    test_result = rmod.log_processor(pr,circuit, degree)
    cpustats, memstats, sysstat = rmod.calc_stats(cstats,mstats)
    data = rmod.prepare_result_dataframe(test_result, sysstat, env, test_id)
    table = 'testresults_circuitbenchmark'
    engine = rmod.pgsql_engine(env['db'])
    data.to_sql(table,engine,if_exists='append')
    ms = rmod.write_mem_time(engine,memstats, test_id)
    cs = rmod.write_cpuall_time(engine,cpustats, test_id)

    url = f'{env["grafana_dashboard_prefix"]}{test_id}'.replace(" ", "")
    print(f'Test Result: {url}')

if __name__ == '__main__':
    main()
    
