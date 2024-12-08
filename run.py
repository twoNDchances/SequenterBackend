from elasticsearch import Elasticsearch
from json import dumps, loads
from logging import info, warning, error, basicConfig, INFO
from os import getenv, _exit
from pika import BlockingConnection, ConnectionParameters, PlainCredentials
from requests import get
from sys import exit
from time import sleep


basicConfig(format=dumps({
    'datetime': '%(asctime)s',
    'loglevel': '[%(levelname)s]',
    'message': '%(message)s'
}), datefmt='%H:%M:%S %d/%m/%Y', level=INFO)

ELASTICSEARCH_HOST         = getenv(key='ELASTICSEARCH_HOST')
ELASTICSEARCH_PORT         = getenv(key='ELASTICSEARCH_PORT')
ELASTICSEARCH_USERNAME     = getenv(key='ELASTICSEARCH_USERNAME')
ELASTICSEARCH_PW           = getenv(key='ELASTICSEARCH_PW')
ELASTICSEARCH_MAX_RESULT   = getenv(key='ELASTICSEARCH_MAX_RESULT')

RABBITMQ_HOST              = getenv(key='RABBITMQ_HOST')
RABBITMQ_MANAGEMENT_PORT   = getenv(key='RABBITMQ_MANAGEMENT_PORT')
RABBITMQ_OPERATION_PORT    = getenv(key='RABBITMQ_OPERATION_PORT')
RABBITMQ_QUEUE_NAME_LISTEN = getenv(key='RABBITMQ_QUEUE_NAME_LISTEN')
RABBITMQ_QUEUE_NAME_ANSWER = getenv(key='RABBITMQ_QUEUE_NAME_ANSWER')
RABBITMQ_USERNAME          = getenv(key='RABBITMQ_USERNAME')
RABBITMQ_PASSWORD          = getenv(key='RABBITMQ_PW')


def main():
    elasticsearch_response = connect_elasticsearch()
    if check_env() is False or elasticsearch_response is False or check_rabbitmq() is False:
        return
    processor(elasticsearch_response=elasticsearch_response)


def check_env():
    info(msg='Checking environment variables...')
    env_vars = {
        'ELASTICSEARCH_HOST': ELASTICSEARCH_HOST,
        'ELASTICSEARCH_PORT': ELASTICSEARCH_PORT,
        'ELASTICSEARCH_USERNAME': ELASTICSEARCH_USERNAME,
        'ELASTICSEARCH_PW': ELASTICSEARCH_PW,
        'ELASTICSEARCH_MAX_RESULT': ELASTICSEARCH_MAX_RESULT,
        'RABBITMQ_HOST': RABBITMQ_HOST,
        'RABBITMQ_MANAGEMENT_PORT': RABBITMQ_MANAGEMENT_PORT,
        'RABBITMQ_OPERATION_PORT': RABBITMQ_OPERATION_PORT,
        'RABBITMQ_QUEUE_NAME_LISTEN': RABBITMQ_QUEUE_NAME_LISTEN,
        'RABBITMQ_QUEUE_NAME_ANSWER': RABBITMQ_QUEUE_NAME_ANSWER,
        'RABBITMQ_USERNAME': RABBITMQ_USERNAME,
        'RABBITMQ_PW': RABBITMQ_PASSWORD,
    }
    if not all([value for _, value in env_vars.items()]):
        error(msg=f'Missing required variables: {[key for key, value in env_vars.items() if not value]}')
        return False
    info(msg='Environment variables [OK]')
    return True


def connect_elasticsearch():
    info(msg='Checking Elasticsearch...')
    try:
        elasticsearch_response = Elasticsearch(
            hosts=f'http://{ELASTICSEARCH_HOST}:{ELASTICSEARCH_PORT}', 
            basic_auth=(ELASTICSEARCH_USERNAME, ELASTICSEARCH_PW)
        )
    except ValueError as error_exception:
        error(msg=str(error_exception))
        return False
    while True:
        if elasticsearch_response.ping() is False:
            warning(msg='Ping to Elasticsearch fail, re-ping after 5 seconds')
            sleep(5)
        else:
            break
    info(msg='Elasticsearch [OK]')
    index_settings = {
        "settings": {
            "index": {
                "max_result_window": int(ELASTICSEARCH_MAX_RESULT)
            }
        }
    }
    info(msg='Checking "responser-modsecurity-executions" index...')
    if not elasticsearch_response.indices.exists(index='responser-modsecurity-executions'):
        info(msg='Creating "responser-modsecurity-executions"')
        elasticsearch_response.indices.create(index="responser-modsecurity-executions", body=index_settings)
        info(msg='Created "responser-modsecurity-executions"')
    info(msg='"responser-modsecurity-executions" [OK]')
    return elasticsearch_response


def check_rabbitmq():
    info(msg='Checking RabbitMQ...')
    try:
        rabbitmq_response = get(
            url=f'http://{RABBITMQ_HOST}:{RABBITMQ_MANAGEMENT_PORT}/api/healthchecks/node', 
            auth=(RABBITMQ_USERNAME, RABBITMQ_PASSWORD)
        )
        if rabbitmq_response.status_code != 200:
            error(msg=f'RabbitMQ connection testing fail, status code {rabbitmq_response.status_code}')
            return False
    except:
        error(msg='Can\'t perform GET request to RabbitMQ, fail for connection testing')
        return False
    info(msg='RabbitMQ [OK]')
    return True


def processor(elasticsearch_response: Elasticsearch):
    connection = BlockingConnection(
        ConnectionParameters(
            host=RABBITMQ_HOST,
            port=RABBITMQ_OPERATION_PORT,
            credentials=PlainCredentials(
                username=RABBITMQ_USERNAME,
                password=RABBITMQ_PASSWORD
            )
        )
    )
    channel = connection.channel()
    channel.queue_declare(queue=RABBITMQ_QUEUE_NAME_LISTEN, durable=True)
    channel.queue_declare(queue=RABBITMQ_QUEUE_NAME_ANSWER, durable=True)
    def callback(ch, method, properties, body: bytes):
        modsecurity_executions = query_all(elasticsearch_response=elasticsearch_response)
        missing_secrule_id = find_missing_or_next([
            modsecurity_execution['_source']['secrule_id'] for modsecurity_execution in modsecurity_executions
        ])
        request_body: dict = loads(body.decode())
        responser_name = request_body.get('responser_name')
        modsec_type = request_body.get('type')
        details: dict = request_body.get('details')
        detail_ip: dict = details.get('ip')
        detail_source_ip = None; detail_anomaly_score = None; detail_paranoia_level = None
        if detail_ip is not None:
            detail_source_ip = detail_ip.get('source_ip')
            detail_anomaly_score = detail_ip.get('anomaly_score')
            detail_paranoia_level = detail_ip.get('paranoia_level')
        detail_rule = details.get('rule')
        detail_payload = details.get('payload')
        detail_hashed_rule = details.get('hashed_rule')
        detail_hashed_payload = details.get('hashed_payload')
        payload = request_body.get('payload')
        if modsec_type == 'full':
            double_secrule = process_double_secrule(
                elasticsearch_response=elasticsearch_response,
                modsecurity_executions=modsecurity_executions,
                responser_name=responser_name,
                modsec_type=modsec_type,
                secrule_id_ip=missing_secrule_id[0],
                secrule_id_chain=missing_secrule_id[1],
                detail_ip=detail_source_ip,
                anomaly_score=detail_anomaly_score,
                paranoia_level=detail_paranoia_level,
                detail_rule=detail_rule,
                detail_payload=detail_payload,
                detail_hashed_rule=detail_hashed_rule,
                detail_hashed_payload=detail_hashed_payload,
                payload=payload
            )
            channel.basic_publish(exchange='', routing_key=RABBITMQ_QUEUE_NAME_ANSWER, body=dumps({
                'responser_name': responser_name,
                'type': 'full',
                'id': {
                    'secrule_id_for_ip': missing_secrule_id[0],
                    'secrule_id_for_chain': missing_secrule_id[1],
                    'secrule_id': None,
                },
                'ip': {
                    'ip_source': detail_source_ip,
                    'anomaly_score': detail_anomaly_score,
                    'paranoia_level': detail_paranoia_level
                },
                'rule': detail_rule,
                'payload': detail_payload,
                'hashed_rule': detail_hashed_rule,
                'hashed_payload': detail_hashed_payload,
                'executions_id': {
                    'for_ip': double_secrule[0],
                    'for_chain': double_secrule[1],
                    'single': None
                }
            }))
        elif modsec_type == 'onlyRegexAndPayload':
            single_secrule = process_single_secrule(
                elasticsearch_response=elasticsearch_response,
                modsecurity_executions=modsecurity_executions,
                responser_name=responser_name,
                modsec_type=modsec_type,
                secrule_id=missing_secrule_id[0],
                detail_ip=None,
                detail_rule=detail_rule,
                detail_payload=detail_payload,
                detail_hashed_rule=detail_hashed_rule,
                detail_hashed_payload=detail_hashed_payload,
                payload=payload
            )
            channel.basic_publish(exchange='', routing_key=RABBITMQ_QUEUE_NAME_ANSWER, body=dumps({
                'responser_name': responser_name,
                'type': 'onlyRegexAndPayload',
                'id': {
                    'secrule_id_for_ip': None,
                    'secrule_id_for_chain': None,
                    'secrule_id': missing_secrule_id[0],
                },
                'ip': None,
                'rule': detail_rule,
                'payload': detail_payload,
                'hashed_rule': detail_hashed_rule,
                'hashed_payload': detail_hashed_payload,
                'executions_id': {
                    'for_ip': None,
                    'for_chain': None,
                    'single': single_secrule[0]
                }
            }))
        elif modsec_type == 'onlyPayload':
            single_secrule = process_single_secrule(
                elasticsearch_response=elasticsearch_response,
                modsecurity_executions=modsecurity_executions,
                responser_name=responser_name,
                modsec_type=modsec_type,
                secrule_id=missing_secrule_id[0],
                detail_ip=None,
                detail_rule=None,
                detail_payload=detail_payload,
                detail_hashed_rule=None,
                detail_hashed_payload=detail_hashed_payload,
                payload=payload
            )
            channel.basic_publish(exchange='', routing_key=RABBITMQ_QUEUE_NAME_ANSWER, body=dumps({
                'responser_name': responser_name,
                'type': 'onlyPayload',
                'id': {
                    'secrule_id_for_ip': None,
                    'secrule_id_for_chain': None,
                    'secrule_id': missing_secrule_id[0],
                },
                'ip': None,
                'rule': None,
                'payload': detail_payload,
                'hashed_rule': None,
                'hashed_payload': detail_hashed_payload,
                'executions_id': {
                    'for_ip': None,
                    'for_chain': None,
                    'single': single_secrule[0]
                }
            }))
        elif modsec_type == 'onlyIP':
            single_secrule = process_single_secrule(
                elasticsearch_response=elasticsearch_response,
                modsecurity_executions=modsecurity_executions,
                responser_name=responser_name,
                modsec_type=modsec_type,
                secrule_id=missing_secrule_id[0],
                detail_ip=detail_source_ip,
                detail_rule=None,
                detail_payload=None,
                detail_hashed_rule=None,
                detail_hashed_payload=None,
                payload=payload
            )
            channel.basic_publish(exchange='', routing_key=RABBITMQ_QUEUE_NAME_ANSWER, body=dumps({
                'responser_name': responser_name,
                'type': 'onlyIP',
                'id': {
                    'secrule_id_for_ip': None,
                    'secrule_id_for_chain': None,
                    'secrule_id': missing_secrule_id[0],
                },
                'ip': {
                    'ip_source': detail_source_ip,
                    'anomaly_score': detail_anomaly_score,
                    'paranoia_level': detail_paranoia_level
                },
                'rule': None,
                'payload': None,
                'hashed_rule': None,
                'hashed_payload': None,
                'executions_id': {
                    'for_ip': None,
                    'for_chain': None,
                    'single': single_secrule[0]
                }
            }))
        elif modsec_type == 'onlyIPAndRegex':
            double_secrule = process_double_secrule(
                elasticsearch_response=elasticsearch_response,
                modsecurity_executions=modsecurity_executions,
                responser_name=responser_name,
                modsec_type=modsec_type,
                secrule_id_ip=missing_secrule_id[0],
                secrule_id_chain=missing_secrule_id[1],
                detail_ip=detail_source_ip,
                anomaly_score=detail_anomaly_score,
                paranoia_level=detail_paranoia_level,
                detail_rule=detail_rule,
                detail_payload=None,
                detail_hashed_rule=detail_hashed_rule,
                detail_hashed_payload=None,
                payload=payload
            )
            channel.basic_publish(exchange='', routing_key=RABBITMQ_QUEUE_NAME_ANSWER, body=dumps({
                'responser_name': responser_name,
                'type': 'onlyIPAndRegex',
                'id': {
                    'secrule_id_for_ip': missing_secrule_id[0],
                    'secrule_id_for_chain': missing_secrule_id[1],
                    'secrule_id': None,
                },
                'ip': {
                    'ip_source': detail_source_ip,
                    'anomaly_score': detail_anomaly_score,
                    'paranoia_level': detail_paranoia_level
                },
                'rule': detail_rule,
                'payload': None,
                'hashed_rule': detail_hashed_rule,
                'hashed_payload': None,
                'executions_id': {
                    'for_ip': double_secrule[0],
                    'for_chain': double_secrule[1],
                    'single': None
                }
            }))
        elif modsec_type == 'onlyRegex':
            single_secrule = process_single_secrule(
                elasticsearch_response=elasticsearch_response,
                modsecurity_executions=modsecurity_executions,
                responser_name=responser_name,
                modsec_type=modsec_type,
                secrule_id=missing_secrule_id[0],
                detail_ip=None,
                detail_rule=detail_rule,
                detail_payload=None,
                detail_hashed_rule=detail_hashed_rule,
                detail_hashed_payload=None,
                payload=payload
            )
            channel.basic_publish(exchange='', routing_key=RABBITMQ_QUEUE_NAME_ANSWER, body=dumps({
                'responser_name': responser_name,
                'type': 'onlyRegex',
                'id': {
                    'secrule_id_for_ip': None,
                    'secrule_id_for_chain': None,
                    'secrule_id': missing_secrule_id[0],
                },
                'ip': None,
                'rule': detail_rule,
                'payload': None,
                'hashed_rule': detail_hashed_rule,
                'hashed_payload': None,
                'executions_id': {
                    'for_ip': None,
                    'for_chain': None,
                    'single': single_secrule[0]
                }
            }))
        elif modsec_type == 'onlyIPAndPayload':
            double_secrule = process_double_secrule(
                elasticsearch_response=elasticsearch_response,
                modsecurity_executions=modsecurity_executions,
                responser_name=responser_name,
                modsec_type=modsec_type,
                secrule_id_ip=missing_secrule_id[0],
                secrule_id_chain=missing_secrule_id[1],
                detail_ip=detail_source_ip,
                anomaly_score=detail_anomaly_score,
                paranoia_level=detail_paranoia_level,
                detail_rule=None,
                detail_payload=detail_payload,
                detail_hashed_rule=None,
                detail_hashed_payload=detail_hashed_payload,
                payload=payload
            )
            channel.basic_publish(exchange='', routing_key=RABBITMQ_QUEUE_NAME_ANSWER, body=dumps({
                'responser_name': responser_name,
                'type': 'onlyIPAndPayload',
                'id': {
                    'secrule_id_for_ip': missing_secrule_id[0],
                    'secrule_id_for_chain': missing_secrule_id[1],
                    'secrule_id': None,
                },
                'ip': {
                    'ip_source': detail_source_ip,
                    'anomaly_score': detail_anomaly_score,
                    'paranoia_level': detail_paranoia_level
                },
                'rule': None,
                'payload': detail_payload,
                'hashed_rule': None,
                'hashed_payload': detail_hashed_payload,
                'executions_id': {
                    'for_ip': double_secrule[0],
                    'for_chain': double_secrule[1],
                    'single': None
                }
            }))
        ch.basic_ack(delivery_tag=method.delivery_tag)
    channel.basic_qos(prefetch_count=1)
    channel.basic_consume(queue=RABBITMQ_QUEUE_NAME_LISTEN, on_message_callback=callback)
    channel.start_consuming()


def find_missing_or_next(numbers: list) -> list[int]:
    if numbers.__len__() == 0:
        return [1, 2]
    full_range = range(1, numbers[-1] + 1)
    missing_numbers = list(set(full_range) - set(numbers))
    if missing_numbers:
        if missing_numbers.__len__() == 1:
            return missing_numbers + [numbers[-1] + 1]
        return missing_numbers
    else:
        return [max(numbers) + 1, max(numbers) + 2]


def query_all(elasticsearch_response: Elasticsearch):
    return elasticsearch_response.search(
        index='responser-modsecurity-executions', 
        query={'match_all': {}}, 
        size=ELASTICSEARCH_MAX_RESULT
    ).raw['hits']['hits']


def process_double_secrule(
    elasticsearch_response: Elasticsearch,
    modsecurity_executions: list,
    responser_name: str,
    modsec_type: str,
    secrule_id_ip: int,
    secrule_id_chain: int,
    detail_ip: str,
    anomaly_score: int,
    paranoia_level: int,
    detail_rule: str,
    detail_payload: str,
    detail_hashed_rule: str,
    detail_hashed_payload: str,
    payload: dict
):
    modsecurity_execution_for_ip = elasticsearch_response.index(index='responser-modsecurity-executions', document={
        'responser_name': responser_name,
        'secrule_id': secrule_id_ip,
        'type': modsec_type,
        'for': 'ip',
        'start': None,
        'detail_ip': detail_ip,
        'anomaly_score': anomaly_score,
        'paranoia_level': paranoia_level,
        'detail_rule': detail_rule,
        'detail_payload': detail_payload,
        'detail_hashed_rule': detail_hashed_rule,
        'detail_hashed_payload': detail_hashed_payload,
        'payload': dumps(payload),
        'relationship': None,
        'real_id_relationship': None,
        'status': None
    })
    while True:
        modsecurity_executions_after = query_all(elasticsearch_response=elasticsearch_response)
        try:
            modsecurity_execution_for_ip_after = elasticsearch_response.get(
                index='responser-modsecurity-executions', 
                id=modsecurity_execution_for_ip['_id']
            )
            if (
                modsecurity_execution_for_ip_after.raw['_source']['secrule_id'] == secrule_id_ip and 
                modsecurity_executions_after.__len__() > modsecurity_executions.__len__()
            ):
                modsecurity_executions = modsecurity_executions_after
                break
        except:
            continue
    modsecurity_execution_for_chain = elasticsearch_response.index(index='responser-modsecurity-executions', document={
        'responser_name': responser_name,
        'secrule_id': secrule_id_chain,
        'type': modsec_type,
        'for': 'chain',
        'start': None,
        'detail_ip': detail_ip,
        'anomaly_score': anomaly_score,
        'paranoia_level': paranoia_level,
        'detail_rule': detail_rule,
        'detail_payload': detail_payload,
        'detail_hashed_rule': detail_hashed_rule,
        'detail_hashed_payload': detail_hashed_payload,
        'payload': dumps(payload),
        'relationship': None,
        'real_id_relationship': None,
        'status': None
    })
    while True:
        modsecurity_executions_after = query_all(elasticsearch_response=elasticsearch_response)
        try:
            modsecurity_execution_for_chain_after = elasticsearch_response.get(
                index='responser-modsecurity-executions', 
                id=modsecurity_execution_for_chain['_id']
            )
            if (
                modsecurity_execution_for_chain_after.raw['_source']['secrule_id'] == secrule_id_chain and 
                modsecurity_executions_after.__len__() > modsecurity_executions.__len__()
            ):
                break
        except:
            continue
    elasticsearch_response.update(
        index='responser-modsecurity-executions',
        id=modsecurity_execution_for_ip['_id'],
        doc={
            'relationship': secrule_id_chain,
            'real_id_relationship': modsecurity_execution_for_chain['_id']
        }
    )
    elasticsearch_response.update(
        index='responser-modsecurity-executions',
        id=modsecurity_execution_for_chain['_id'],
        doc={
            'relationship': secrule_id_ip,
            'real_id_relationship': modsecurity_execution_for_ip['_id']
        }
    )
    return (
        modsecurity_execution_for_ip['_id'],
        modsecurity_execution_for_chain['_id']
    )


def process_single_secrule(
    elasticsearch_response: Elasticsearch,
    modsecurity_executions: list,
    responser_name: str,
    modsec_type: str,
    secrule_id: int,
    detail_ip: str,
    detail_rule: str,
    detail_payload: str,
    detail_hashed_rule: str,
    detail_hashed_payload: str,
    payload: dict
):
    modsecurity_execution = elasticsearch_response.index(index='responser-modsecurity-executions', document={
        'responser_name': responser_name,
        'secrule_id': secrule_id,
        'type': modsec_type,
        'for': None,
        'start': None,
        'detail_ip': detail_ip,
        'anomaly_score': None,
        'paranoia_level': None,
        'detail_rule': detail_rule,
        'detail_payload': detail_payload,
        'detail_hashed_rule': detail_hashed_rule,
        'detail_hashed_payload': detail_hashed_payload,
        'payload': dumps(payload),
        'relationship': None,
        'real_id_relationship': None,
        'status': None
    })
    while True:
        modsecurity_executions_after = query_all(elasticsearch_response=elasticsearch_response)
        try:
            modsecurity_execution_after = elasticsearch_response.get(
                index='responser-modsecurity-executions', 
                id=modsecurity_execution['_id']
            )
            if (
                modsecurity_execution_after.raw['_source']['secrule_id'] == secrule_id and 
                modsecurity_executions_after.__len__() > modsecurity_executions.__len__()
            ):
                break
        except:
            continue
    return (
        modsecurity_execution['_id'],
    )

if __name__ == '__main__':
    try:
        main()
    except KeyboardInterrupt:
        try:
            exit(0)
        except SystemExit:
            _exit(0)
