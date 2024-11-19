from sqlalchemy import func, asc, desc
from sqlalchemy.exc import SQLAlchemyError, IntegrityError, OperationalError
import RNS, json, time
from config.utils import (get_hash_for_password, check_hash_for_password,
                                create_response, RateLimiter, RESPONSE_CODES as resp)
from db.schema import (Member, Device, sex, member_state,
                            InviteCode, MEMBER_IMMUTABLE_FIELDS,
                            DEVICE_IMMUTABLE_FIELDS)

limiter1 = RateLimiter('validate_invite_code',5,60)
limiter2 = RateLimiter('verify_password',5,60)
limiter3 = RateLimiter('get_similar_contacts_for_rns',5,60)

class handlers:

    @staticmethod
    def add_member(session, path, data, request_id, link_id, remote_identity, requested_at):
        try:
            if type(remote_identity) == type(None):
                return create_response('0x00', resp.get('0x00'), "Invalid identity")
            
            data = json.loads(data)
            if type(data) is not dict:
                print(type(data))
                return create_response('0x01', resp.get('0x01'), "Invalid Data")
            
            if not data.get('invite_code'):
                return create_response('0x02', resp.get('0x02'), 'invalid invite code')
            else:
                ic = handlers.validate_invite_code(session, path, data, request_id, link_id, remote_identity, requested_at)
                if ic.status == 'RESULT_OK':
                    invite_code = session.query(InviteCode).filter_by(code=data.get('invite_code')).first()
                else:
                    return ic
                
            if isinstance(data['sex'], int) and (data['sex'] == 0 or data['sex'] == 1):
                data['sex'] = sex(data['sex'])
            elif isinstance(data['sex'], str) and (data['sex'] == "female" or data['sex'] == "male"):
                data['sex'] = sex[data['sex']]
            else:
                return create_response('0x02', resp.get('0x02'), "Invalid Sex type")
            
            member = Member.from_json(data,remote_identity)
            session.add(member)

            setattr(invite_code, 'invitee', member.RNS_id)
            setattr(invite_code, 'used_at', int(time.time()))

            session.commit()

            return create_response('201', resp.get('201'), "Member registeration success")
            
        except IntegrityError as e:
            # Handle database integrity errors (e.g., unique constraint violations)
            session.rollback()
            return create_response('409', resp.get('409'), f"IntegrityError: {str(e)}")

        except OperationalError as e:
            # Handle operational errors (e.g., database connection issues)
            session.rollback()
            return create_response('503', resp.get('503'), f"OperationalError: {str(e)}")

        except SQLAlchemyError as e:
            # Handle other general SQLAlchemy errors
            session.rollback()
            return create_response('500', resp.get('500'), f"SQLAlchemyError: {str(e)}")
        
        except TypeError as e:
            # Handle type errors specifically
            session.rollback()
            return create_response('0x01', resp.get('0x01'), f"TypeError: {str(e)}")

        except Exception as e:
            # Handle any other exceptions
            session.rollback()
            return create_response('500', resp.get('500'), f"Error: {str(e)}")

    @staticmethod
    def get_member(session, path, data, request_id, link_id, remote_identity, requested_at):
        try:
            if not isinstance(remote_identity, type(RNS.Identity())):
                return create_response('0x00', resp.get('0x00'), "Invalid identity")
            
            member = session.query(Member).filter_by(RNS_id=str(remote_identity)).first()

            if isinstance(member, type(None)):
                return create_response('0x03', resp.get('0x03'), 'Member not found')
            
            if member.state == member_state.restricted or member.state == member_state.onhold:
                return create_response('403', resp.get('403'), 'Access is restricted')        
            
            return create_response('200', resp.get('200'), 'Member retieve success', member.to_json())   
            
        except Exception as e:
            return create_response('500', resp.get('500'), f"Error: {str(e)}")

    @staticmethod    
    def get_member_status_with_rns(session, path, data, request_id, link_id, remote_identity, requested_at):
        try:
            if type(remote_identity) == type(None):
                return create_response('0x00', resp.get('0x00'), "Invalid identity")
            
            member = session.query(Member).filter_by(RNS_id=str(remote_identity)).first()

            if isinstance(member, type(None)):
                return create_response('0x03', resp.get('0x03'), 'Member not found')

            return create_response('200', resp.get('200'),'status fetched',{'state':member.state})
        
        except Exception as e:
            return create_response('500', resp.get('500'), f"Error: {str(e)}")

    @staticmethod
    def validate_invite_code(session, path, data, request_id, link_id, remote_identity, requested_at):
        try:
            if not isinstance(remote_identity, type(RNS.Identity())):
                return create_response('0x00', resp.get('0x00'), "Invalid identity")
            
            if not limiter1.handle_request(str(remote_identity)):
                return create_response('429', resp.get('429'), 'Unusual activity detected')
            
            data = json.loads(data)
            if type(data) is not dict:
                return create_response('0x01', resp.get('0x01'), "Invalid Data")
            
            if not data.get('invite_code'):
                return create_response('0x02', resp.get('0x02'), 'invalid invite code')
            else:
                invite_code = data.get('invite_code')

                if len(invite_code) != 5:
                    return create_response('0x02', resp.get('0x02'), 'invalid invite code')
                
                invite_code = session.query(InviteCode).filter_by(code=invite_code).first()

                if type(invite_code) == type(None):
                    return create_response('0x02', resp.get('0x02'), 'invalid invite code')
                    
                if invite_code.is_valid == False:
                    return create_response('0x05', resp.get('0x05'), 'invite code is revoked')
                    
                if invite_code.used_at != None:
                    return create_response('0x06', resp.get('0x06'), 'invite code is used')
                    
                return create_response('200', resp.get('200'), 'invite code is valid')

        except TypeError as e:
            return create_response('0x01', resp.get('0x01'), f"TypeError: {str(e)}")

        except Exception as e:
            return create_response('500', resp.get('500'), f"Error: {str(e)}")

    @staticmethod
    def add_device(session, path, data, request_id, link_id, remote_identity, requested_at):
        try:
            if type(remote_identity) == type(None):
                return create_response('0x00', resp.get('0x00'), "Invalid identity")
            
            data = json.loads(data)
            if type(data) is not dict:
                print(type(data))
                return create_response('0x01', resp.get('0x01'), "Invalid Data") 
            
            print(data)
            
            _device = Device.from_json(data,remote_identity)
            session.add(_device)
            session.commit()

            return create_response('200', resp.get('200'), 'Device added successfully' ) 
            
        except IntegrityError as e:
            # Handle database integrity errors (e.g., unique constraint violations)
            session.rollback()
            return create_response('409', resp.get('409'), f"IntegrityError: {str(e.orig)}")

        except OperationalError as e:
            # Handle operational errors (e.g., database connection issues)
            session.rollback()
            return create_response('503', resp.get('503'), f"OperationalError: {str(e.orig)}")

        except SQLAlchemyError as e:
            # Handle other general SQLAlchemy errors
            session.rollback()
            return create_response('500', resp.get('500'), f"SQLAlchemyError: {str(e)}")
        
        except TypeError as e:
            # Handle type errors specifically
            return create_response('0x01', resp.get('0x01'), f"TypeError: {str(e)}")

        except Exception as e:
            # Handle any other exceptions
            return create_response('500', resp.get('500'), f"Error: {str(e)}")

    @staticmethod
    def get_all_devices_for_member_with_rns(session, path, data, request_id, link_id, remote_identity, requested_at):
        try:
            if not isinstance(remote_identity, type(RNS.Identity())):
                return create_response('0x00', resp.get('0x00'), "Invalid identity")
            
            _devices = session.query(Device).filter_by(device_associated_user_id=str(remote_identity)).all()

            if not len(_devices):
                return create_response('0x04', resp.get('0x04'), 'No device found')
            
            for i in range(len(_devices)):
                _devices[i] = _devices[i].to_json()

            return create_response('200', resp.get('200'), 'Devices fetch success', _devices)
            
        except Exception as e:
            return create_response('500', resp.get('500'), f"Error: {str(e)}")

    @staticmethod
    def get_device_by_device_id(session, path, data, request_id, link_id, remote_identity, requested_at):
        try:
            if type(remote_identity) == type(None):
                return create_response('0x00', resp.get('0x00'), "Invalid identity")
            
            data = json.loads(data)
            if type(data) is not dict:
                print(type(data))
                return create_response('0x01', resp.get('0x01'), "Invalid Data")
            
            if data == None:
                return create_response('0x01', resp.get('0x01'), "Invalid Data")
            elif data.get('filter') == None:
                return create_response('0x02', resp.get('0x02'), 'Invalid Filters')
            else:
                if data.get('filter') == 'device_id':
                    if data.get('device_id', None) != None:
                        _device = session.query(Device).filter_by(device_id=data.get('device_id')).first()
                    else:
                        return create_response('0x04', resp.get('0x04'), 'Invalid Device ID')
                    
                elif data.get('filter') == 'device_rns_id':
                    if data.get('device_rns_id', None) != None:
                        _device = session.query(Device).filter_by(device_rns_id=data.get('device_rns_id')).first()
                    else:
                        return create_response('0x04', resp.get('0x04'), 'Invalid device_rns_id')
                
                if isinstance(_device, type(None)):
                        return create_response('0x04', resp.get('0x04'), 'Device not found')

                return create_response('200', resp.get('200'), 'Device Found successfully', _device.to_json())
            
        except Exception as e:
            return create_response('500', resp.get('500'), f"Error: {str(e)}")
   
    @staticmethod
    def get_invite_codes_for_member_with_rns_id(session, path, data, request_id, link_id, remote_identity, requested_at):
        try:
            if not isinstance(remote_identity, type(RNS.Identity())):
                return create_response('0x00', resp.get('0x00'), "Invalid identity")
            
            codes = session.query(InviteCode).filter_by(inviter=str(remote_identity), is_valid=True, used_at=None).all()

            if not len(codes):
                return create_response('0x04', resp.get('0x04'), 'Invite code not found')

            for i in range(len(codes)):
                codes[i] = codes[i].to_json()

            return create_response('200', resp.get('200'), 'Invite code fetch success', codes)
            
        except Exception as e:
            return create_response('500', resp.get('500'), f"Error: {str(e)}")
    
    @staticmethod  
    def get_device_status_with_filter(session, path, data, request_id, link_id, remote_identity, requested_at):
        try:
            if type(remote_identity) == type(None):
                return create_response('0x00', resp.get('0x00'), "Invalid identity")
            
            data = json.loads(data)
            if type(data) is not dict:
                print(type(data))
                return create_response('0x01', resp.get('0x01'), "Invalid Data")
            
            if data == None:
                raise Exception("No ID Found")
            elif data.get('filter') == None:
                return create_response('0x02', resp.get('0x02'), 'Invalid Filters')
            else:
                if data.get('filter') == 'device_id':
                    if data.get('device_id', None) != None:
                        _device = session.query(Device).filter_by(device_id=data.get('device_id')).first()
                    else:
                        return create_response('0x04', resp.get('0x04'), 'Invalid Device ID')
                    
                elif data.get('filter') == 'device_rns_id':
                    if data.get('device_rns_id', None) != None:
                        _device = session.query(Device).filter_by(device_rns_id=data.get('device_rns_id')).first()
                    else:
                        return create_response('0x04', resp.get('0x04'), 'Invalid device_rns_id')
                
                
                if isinstance(_device, type(None)):
                        return create_response('0x04', resp.get('0x04'), 'Device not found', [])

                return create_response('200', resp.get('200'), 'Device Found successfully', {'status':_device.status})
            
        except Exception as e:
            return create_response('500', resp.get('500'), f"Error: {str(e)}")
    
    @staticmethod
    def update_member_with_rns_id(session, path, data, request_id, link_id, remote_identity, requested_at):
        try:
            if type(remote_identity) == type(None):
                return create_response('0x00', resp.get('0x00'), "Invalid identity")
            
            data = json.loads(data)
            if type(data) is not dict:
                print(type(data))
                return create_response('0x01', resp.get('0x01'), "Invalid Data")
            
            member = session.query(Member).filter_by(RNS_id=str(remote_identity)).first()

            if member:
                for key, value in data.items():
                    if hasattr(member, key) and key not in MEMBER_IMMUTABLE_FIELDS:
                        setattr(member, key, value)
                
                session.commit()
                return create_response('200', resp.get('200'), 'Member updated sucessfully')
            else:
                return create_response('0x03', resp.get('0x03'), 'No member found')
            
        except Exception as e:
            return create_response('500', resp.get('500'), f"Error: {str(e)}")
    
    @staticmethod
    def update_device_with_filters(session, path, data, request_id, link_id, remote_identity, requested_at):
        try:
            if type(remote_identity) == type(None):
                return create_response('0x00', resp.get('0x00'), "Invalid identity")
            
            data = json.loads(data)
            if type(data) is not dict:
                print(type(data))
                return create_response('0x01', resp.get('0x01'), "Invalid Data")
            
            if not data:
                return create_response('0x01', resp.get('0x01'), "Invalid Data")
            elif data.get('filter') == None:
                return create_response('0x02', resp.get('0x02'), 'Invalid Filters')
            else:
                if data.get('filter') == 'device_id':
                    if data.get('device_id', None) != None:
                        _device = session.query(Device).filter_by(device_id=data.get('device_id')).first()

                        if _device:
                            if _device.device_associated_user_id == str(remote_identity):
                                for key, value in data.items():
                                    if hasattr(_device, key) and key not in DEVICE_IMMUTABLE_FIELDS:
                                        setattr(_device, key, value)
                                
                                session.commit()
                                return create_response('200', resp.get('200'), 'Device updated sucessfully')

                            else:
                                return create_response('0x04', resp.get('0x04'), 'Invaild associated user ID')
                        else:
                            return create_response('0x04', resp.get('0x04'), 'Device not found')
                    else:
                        return create_response('0x04', resp.get('0x04'), 'Invalid Device ID')
                    
                elif data.get('filter') == 'device_rns_id':
                    if data.get('device_id', None) != None:
                        _device = session.query(Device).filter_by(device_rns_id=data.get('device_rns_id')).first()

                        if _device:
                            if _device.device_associated_user_id == str(remote_identity):
                                for key, value in data.items():
                                    if hasattr(_device, key) and key not in MEMBER_IMMUTABLE_FIELDS:
                                        setattr(_device, key, value)
                                
                                session.commit()
                                return create_response('200', resp.get('200'), 'Device updated sucessfully')

                            else:
                                return create_response('0x04', resp.get('0x04'), 'Invaild associated user ID')
                        else:
                            return create_response('0x04', resp.get('0x04'), 'Device not found')
                    else:
                        return create_response('0x04', resp.get('0x04'), 'Invalid Device ID')
            
        except Exception as e:
            return create_response('500', resp.get('500'), f"Error: {str(e)}")
    
    @staticmethod
    def reset_password_for_rns_id(session, path, data, request_id, link_id, remote_identity, requested_at):
        try:
            if type(remote_identity) == type(None):
                return create_response('0x00', resp.get('0x00'), "Invalid identity")

            data = json.loads(data)
            if type(data) is not dict:
                print(type(data))
                return create_response('0x01', resp.get('0x01'), "Invalid Data")
            
            if data.get('new_password', None) != None:
                member = session.query(Member).filter_by(RNS_id=str(remote_identity)).first()
                if member:
                    password_hash = get_hash_for_password(data.get('new_password'))
                    member.password = password_hash
                    session.commit()
                    return create_response('200', resp.get('200'), 'Password reset sucessfull')

                else:
                    return create_response('0x04', resp.get('0x04'), 'Member not found')
            else:
                return create_response('0x02', resp.get('0x02'), 'Invalid new password')
        
        except Exception as e:
            return create_response('500', resp.get('500'), f"Error: {str(e)}")
    
    @staticmethod
    def change_password(session, path, data, request_id, link_id, remote_identity, requested_at):
        try:
            if type(remote_identity) == type(None):
                return create_response('0x00', resp.get('0x00'), "Invalid identity")
            
            data = json.loads(data)
            if type(data) is not dict:
                print(type(data))
                return create_response('0x01', resp.get('0x01'), "Invalid Data")
            
            if data.get('old_password', None) != None and data.get('new_password', None) != None:
                member = session.query(Member).filter_by(RNS_id=str(remote_identity)).first()
                if member:
                    if check_hash_for_password(data.get('old_password'), member.password):
                        member.password = get_hash_for_password(data.get("new_password"))
                        session.commit()
                        return create_response('200', resp.get('200'), 'Password change sucessfull')
                    else:
                        return create_response('0x02', resp.get('0x02'), 'Invalid old password')
                else:
                    return create_response('0x03', resp.get('0x03'), 'Member not found')
            else:
                return create_response('0x02', resp.get('0x02'), 'Invalid password')

        except Exception as e:
            return create_response('500', resp.get('500'), f"Error: {str(e)}")

    @staticmethod
    def verify_password(session, path, data, request_id, link_id, remote_identity, requested_at):
        try:
            if type(remote_identity) == type(None):
                return create_response('0x00', resp.get('0x00'), "Invalid identity")
            
            if not limiter2.handle_request(str(remote_identity)):
                return create_response('429', resp.get('429'), 'Unusual activity detected')
            
            data = json.loads(data)
            if type(data) is not dict:
                print(type(data))
                return create_response('0x01', resp.get('0x01'), "Invalid Data")
            
            if data.get('password', None) != None:
                member = session.query(Member).filter_by(RNS_id=str(remote_identity)).first()
                if member:
                    print(data.get('password'))
                    if check_hash_for_password(data.get('password'), member.password):
                        return create_response('200', resp.get('200'), 'Password is correct',  data={'is_correct':True})
                    else:
                        return create_response('0x02', resp.get('0x02'), 'Invalid password',  data={'is_correct':False})
                else:
                    return create_response('0x03', resp.get('0x03'), 'Member not found',  data={'is_correct':False})
            else:
                return create_response('0x02', resp.get('0x02'), 'Invalid password B', data={'is_correct':False})

        except Exception as e:
            return create_response('500', resp.get('500'), f"Error: {str(e)}",  data={'is_correct':False})

    @staticmethod
    def get_similar_contacts_for_rns(session, path, data, request_id, link_id, remote_identity, requested_at):
        try:
            if type(remote_identity) == type(None):
                return create_response('0x00', resp.get('0x00'), "Invalid identity")
            
            if not limiter3.handle_request(str(remote_identity)):
                return create_response('429', resp.get('429'), 'Unusual activity detected')
            
            data = json.loads(data)
            if type(data) is not dict:
                print(type(data))
                return create_response('0x01', resp.get('0x01'), "Invalid Data")
            
            order_by = data.get('order_by', 'ASC').upper()
        
            member = session.query(Member).filter_by(id=str(remote_identity)).first()
        
            if not member:
                return create_response('0x03', resp.get('0x03'), 'Member not found')
            
            order_func = asc if order_by == 'ASC' else desc
        
            similar_members = session.query(Member).filter(
                (Member.country == member.country) |
                (Member.state_name == member.state_name) |
                (Member.city == member.city) |
                (Member.occupation == member.occupation) |
                (Member.skills == member.skills)
            ).order_by(order_func(Member.RNS_id)).all()

            result = [m.to_json() for m in similar_members]
        
            return create_response('200', resp.get('200'), 'Found similar contacts', result)
        except Exception as e:
            pass

    @staticmethod
    def client_connected(link):
        RNS.log("Client connected")
        link.set_link_closed_callback(handlers.client_disconnected)

    @staticmethod
    def client_disconnected(link):
        RNS.log("Client disconnected")

