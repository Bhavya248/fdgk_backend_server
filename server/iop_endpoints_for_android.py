import rsa, json, iop
from project.config.utils import create_response, RESPONSE_CODES as resp
        
class iop_handlers:
    
    def get_phrase_handler(session, path, data, request_id, link_id, remote_identity, requested_at):
        try:
            data = json.loads(data)
            if type(data) is not dict:
                print(type(data))
                return create_response('0x01', resp.get('0x01'), "Invalid Data")
            
            phrase = iop.generate_phrase()
            response_data = {"phrase": phrase}

            return create_response('200', resp.get('200'), 'Phrase generated', response_data)
        
        except Exception as e:
            return create_response('500', '500', f'Error: {str(e)}')



    def get_hyd_vault_handler(session, path, data, request_id, link_id, remote_identity, requested_at):
        try:
            data = json.loads(data)
            if type(data) is not dict:
                print(type(data))
                return create_response('0x01', resp.get('0x01'), "Invalid Data")
            
            password = data['password']
            phrase = data['phrase']
            
            hyd_vault = iop.get_hyd_vault(phrase, password)
            
            response_data = {
                "hyd_vault": hyd_vault
            }

            return create_response('200', resp.get('200'), 'Phrase generated', response_data)

        except Exception as e:
            return create_response('500', '500', f'Error: {str(e)}')


    def get_morpheus_vault_handler(session, path, data, request_id, link_id, remote_identity, requested_at):
        try:
            data = json.loads(data)
            if type(data) is not dict:
                print(type(data))
                return create_response('0x01', resp.get('0x01'), "Invalid Data")
            
            password = data['password']
            phrase = data['phrase']

            morpheus_vault = iop.get_morpheus_vault(phrase, password)
            response_data = {"morpheus_vault": morpheus_vault}

            return create_response('200', resp.get('200'), 'Phrase generated', response_data)

        except Exception as e:
            return create_response('500', '500', f'Error: {str(e)}')
        

    def get_new_account_on_vault_handler(session, path, data, request_id, link_id, remote_identity, requested_at):
        try:
            data = json.loads(data)
            if type(data) is not dict:
                print(type(data))
                return create_response('0x01', resp.get('0x01'), "Invalid Data")
            
            password = data['password']
            vault = data['vault']
            account = data['account']

            new_vault = iop.get_new_acc_on_vault(vault, password.decode("utf8"), int(account))
            response_data = {"vault": new_vault}

            return create_response('200', resp.get('200'), 'Phrase generated', response_data)

        except Exception as e:
            return create_response('500', '500', f'Error: {str(e)}')


    def get_wallet_handler(session, path, data, request_id, link_id, remote_identity, requested_at):
        try:
            data = json.loads(data)
            if type(data) is not dict:
                print(type(data))
                return create_response('0x01', resp.get('0x01'), "Invalid Data")
            
            vault = data['vault']
            account = data['account']

            address = iop.get_wallet(vault, int(account))
            response_data = {'address':address}

            return create_response('200', resp.get('200'), 'Phrase generated', response_data)

        except Exception as e:
            return create_response('500', '500', f'Error: {str(e)}')


    def generate_did_by_morpheus_handler(session, path, data, request_id, link_id, remote_identity, requested_at):
        try:
            data = json.loads(data)
            if type(data) is not dict:
                print(type(data))
                return create_response('0x01', resp.get('0x01'), "Invalid Data")
            
            password = data['password']
            vault = data['vault']

            did = iop.generate_did_by_morpheus(vault, password)
            response_data = {"did": did}

            return create_response('200', resp.get('200'), 'Phrase generated', response_data)

        except Exception as e:
            return create_response('500', '500', f'Error: {str(e)}')


    def sign_witness_statement_handler(session, path, data, request_id, link_id, remote_identity, requested_at):
        try:
            data = json.loads(data)
            if type(data) is not dict:
                print(type(data))
                return create_response('0x01', resp.get('0x01'), "Invalid Data")
            
            password = data['password']
            vault = data['vault']
            statement_data = data['data']

            signed_statement = iop.sign_witness_statement(vault, password, statement_data)
            response_data = {"signed": signed_statement}

            return create_response('200', resp.get('200'), 'Phrase generated', response_data)

        except Exception as e:
            return create_response('500', '500', f'Error: {str(e)}')


    def sign_did_statement_handler(session, path, data, request_id, link_id, remote_identity, requested_at):
        try:
            data = json.loads(data)
            if type(data) is not dict:
                print(type(data))
                return create_response('0x01', resp.get('0x01'), "Invalid Data")
            
            password = data['password']
            vault = data['vault']
            data_hex = data['data']
            statement_data = bytes.fromhex(data_hex)

            signature, public_key = iop.sign_did_statement(vault, password, statement_data)
            response_data = {"signature": signature, "public_key": public_key}

            return create_response('200', resp.get('200'), 'Phrase generated', response_data)

        except Exception as e:
            return create_response('500', '500', f'Error: {str(e)}')


    def get_nonce_handler(session, path, data, request_id, link_id, remote_identity, requested_at):
        try:
            nonce = iop.generate_nonce()
            response_data = {'nonce':nonce}

            return create_response('200', resp.get('200'), 'Phrase generated', response_data)

        except Exception as e:
            return create_response('500', '500', f'Error: {str(e)}')


    def sign_transaction_handler(session, path, data, request_id, link_id, remote_identity, requested_at):
        try:
            data = json.loads(data)
            if type(data) is not dict:
                print(type(data))
                return create_response('0x01', resp.get('0x01'), "Invalid Data")
            
            password = data['password']
            vault = data['vault']
            salt = data['salt']
            receiver = data['receiver']
            amount = data['amount']
            nonce = data['nonce']
            hash_received = data['hash']
            account = data['account']
            
            message = receiver + amount + nonce + account + salt + password
            computed_hash = rsa.compute_hash(message.encode(), 'SHA-1')
            
            if computed_hash != hash_received:
                return create_response('400', '400', 'Invalid hash')
            
            signed_transaction = iop.generate_transaction(vault, receiver, amount, nonce, password, account)
            response_data = {'transaction': signed_transaction}

            return create_response('200', resp.get('200'), 'Phrase generated', response_data)
        
        except Exception as e:
            return create_response('500', '500', f'Error: {str(e)}')
        



