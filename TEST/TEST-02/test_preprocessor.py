from copy import deepcopy

import pytest

from src.preprocessor import preprocess_event


def event():
    return {'timestamp': '2026-10-12T14:00:00+07:00',
            'network': {'src_ip': ' 10.0.0.1 ', 'dst_ip': '10.0.0.2', 'protocol': 6,
                        'length': 60, 'ttl': 64, 'id': 1},
            'transport': {'protocol': ' tcp ', 'src_port': 12345, 'dst_port': 80, 'flags': 'A'},
            'application': {'protocol': 'http', 'uri': '/Admin/%2f?a=A',
                            'headers': {'HOST': 'Example.org', 'X-Test': ['a'], 'x-test': ['b']}}}


def test_t05_normalization_preserves_original():
    original = event()
    before = deepcopy(original)
    result = preprocess_event(original)
    assert original == before
    assert result['application'] == before['application']
    norm = result['normalized']
    assert norm['timestamp'] == '2026-10-12T07:00:00.000000Z'
    assert norm['network']['src_ip'] == '10.0.0.1'
    assert norm['transport']['protocol'] == 'TCP'
    assert norm['application']['headers']['x-test'] == ['a', 'b']
    assert norm['application']['uri'] == '/Admin/%2f?a=A'
    assert result['preprocess_status'] == 'valid'


def test_dns_and_missing_optional_fields():
    data = event()
    data['application'] = {'protocol': 'dns', 'questions': [{'name': 'EXAMPLE.ORG', 'type': 1}]}
    data['network'].pop('ttl')
    result = preprocess_event(data)
    assert result['normalized']['application']['questions'][0]['name'] == 'example.org.'
    assert result['normalized']['application']['answers'] == []
    assert result['normalized']['network']['ttl'] is None
    assert result['preprocess_status'] == 'partial'


@pytest.mark.parametrize('port', [-1, 65536, True, '80', None])
def test_invalid_ports(port):
    data = event()
    data['transport']['dst_port'] = port
    result = preprocess_event(data, invalid_policy='drop')
    assert result['preprocess_status'] == 'invalid'
    assert result['processing_action'] == 'drop'


@pytest.mark.parametrize('data', [None, [], {}, {'network': []}, {'application': 'bad'}])
def test_t14_malformed(data):
    result = preprocess_event(data)
    assert result['preprocess_status'] == 'invalid'
    assert result['reason']


def test_unsupported_policy():
    data = event()
    data['application'] = {'protocol': 'UNKNOWN'}
    assert preprocess_event(data)['processing_action'] == 'keep'
    result = preprocess_event(data, unsupported_policy='drop')
    assert result['processing_action'] == 'drop'
    assert result['preprocess_status'] == 'partial'


def test_timestamp_and_protocol_mismatch():
    data = event()
    data['timestamp'] = '2026-10-12T12:00:00'
    data['network']['protocol'] = 17
    result = preprocess_event(data)
    assert 'timestamp:invalid_or_missing' in result['reason']
    assert 'transport_protocol_mismatch' in result['reason']


def test_decoder_error_propagates():
    data = event()
    data['decode_status'] = 'partial'
    assert preprocess_event(data)['preprocess_status'] == 'partial'


def test_bad_config():
    with pytest.raises(ValueError):
        preprocess_event(event(), invalid_policy='ignore')
