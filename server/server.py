import RNS, os, signal, sys
from db.db_connection import initialize_database
from server.handlers import handlers
# from project.server.iop_endpoints_for_android import iop_handlers

APP_NAME = "FDGK_backend_server"

def signal_handler(sig, frame):
    RNS.log("Exiting gracefully...")
    RNS.exit()
    sys.exit(0)
    
def server(configpath):
    # Initialize Reticulum
    if configpath == None or configpath == "":
        configpath = os.getcwd() + '/reticulum-config'
    reticulum = RNS.Reticulum(configpath)

    # Initialize database session
    db_session = initialize_database()

    # Create server identity and destination
    server_identity = RNS.Identity.from_file(configpath + "/storage/identities/server_identity")
    server_destination = RNS.Destination(
        server_identity,
        RNS.Destination.IN,
        RNS.Destination.SINGLE,
        APP_NAME,
        "BACKEND"
    )

    server_destination.set_link_established_callback(handlers.client_connected)
    server_destination.register_request_handler(
        "/member/register",
        response_generator=lambda path, data, request_id, link_id, remote_identity, requested_at: handlers.add_member(db_session, path, data, request_id, link_id, remote_identity, requested_at),
        allow=RNS.Destination.ALLOW_ALL
    )
    server_destination.register_request_handler(
        "/member/get-member",
        response_generator=lambda path,data, request_id, link_id, remote_identity, requested_at: handlers.get_member(db_session, path, data, request_id, link_id, remote_identity, requested_at),
        allow=RNS.Destination.ALLOW_ALL
    )
    server_destination.register_request_handler(
        "/member/get-member-status",
        response_generator=lambda path,data, request_id, link_id, remote_identity, requested_at: handlers.get_member_status_with_rns(db_session, path, data, request_id, link_id, remote_identity, requested_at),
        allow=RNS.Destination.ALLOW_ALL
    )
    server_destination.register_request_handler(
        "/member/validate-ic",
        response_generator=lambda path,data, request_id, link_id, remote_identity, requested_at: handlers.validate_invite_code(db_session, path, data, request_id, link_id, remote_identity, requested_at),
        allow=RNS.Destination.ALLOW_ALL
    )
    server_destination.register_request_handler(
        "/device/add-device",
        response_generator=lambda path,data, request_id, link_id, remote_identity, requested_at: handlers.add_device(db_session, path, data, request_id, link_id, remote_identity, requested_at),
        allow=RNS.Destination.ALLOW_ALL
    )
    server_destination.register_request_handler(
        "/device/get-devices-for-member",
        response_generator=lambda path,data, request_id, link_id, remote_identity, requested_at: handlers.get_all_devices_for_member_with_rns(db_session, path, data, request_id, link_id, remote_identity, requested_at),
        allow=RNS.Destination.ALLOW_ALL
    )
    server_destination.register_request_handler(
        "/device/get-device-byid",
        response_generator=lambda path,data, request_id, link_id, remote_identity, requested_at: handlers.get_device_by_device_id(db_session, path, data, request_id, link_id, remote_identity, requested_at),
        allow=RNS.Destination.ALLOW_ALL
    )
    server_destination.register_request_handler(
        "/member/get-invite-codes",
        response_generator=lambda path,data, request_id, link_id, remote_identity, requested_at: handlers.get_invite_codes_for_member_with_rns_id(db_session, path, data, request_id, link_id, remote_identity, requested_at),
        allow=RNS.Destination.ALLOW_ALL
    )
    server_destination.register_request_handler(
        "/device/device-status",
        response_generator=lambda path,data, request_id, link_id, remote_identity, requested_at: handlers.get_device_status_with_filter(db_session, path, data, request_id, link_id, remote_identity, requested_at),
        allow=RNS.Destination.ALLOW_ALL
    )
    server_destination.register_request_handler(
        "/member/update-device",
        response_generator=lambda path,data, request_id, link_id, remote_identity, requested_at: handlers.update_member_with_rns_id(db_session, path, data, request_id, link_id, remote_identity, requested_at),
        allow=RNS.Destination.ALLOW_ALL
    )
    server_destination.register_request_handler(
        "/device/update-device",
        response_generator=lambda path,data, request_id, link_id, remote_identity, requested_at: handlers.update_device_with_filters(db_session, path, data, request_id, link_id, remote_identity, requested_at),
        allow=RNS.Destination.ALLOW_ALL
    )
    server_destination.register_request_handler(
        "/member/reset-password",
        response_generator=lambda path,data, request_id, link_id, remote_identity, requested_at: handlers.reset_password_for_rns_id(db_session, path, data, request_id, link_id, remote_identity, requested_at),
        allow=RNS.Destination.ALLOW_ALL
    )
    server_destination.register_request_handler(
        "/member/change-password",
        response_generator=lambda path,data, request_id, link_id, remote_identity, requested_at: handlers.change_password(db_session, path, data, request_id, link_id, remote_identity, requested_at),
        allow=RNS.Destination.ALLOW_ALL
    )
    server_destination.register_request_handler(
        "/member/verify-password",
        response_generator=lambda path,data, request_id, link_id, remote_identity, requested_at: handlers.verify_password(db_session, path, data, request_id, link_id, remote_identity, requested_at),
        allow=RNS.Destination.ALLOW_ALL
    )
    # server_destination.register_request_handler(
    # "/phrase",
    # response_generator=lambda path, data, request_id, link_id, remote_identity, requested_at: iop_handlers.get_phrase_handler(None, path, data, request_id, link_id, remote_identity, requested_at),
    # allow=RNS.Destination.ALLOW_ALL
    # )

    # server_destination.register_request_handler(
    #     "/get_hyd_vault",
    #     response_generator=lambda path, data, request_id, link_id, remote_identity, requested_at: iop_handlers.get_hyd_vault_handler(None, path, data, request_id, link_id, remote_identity, requested_at),
    #     allow=RNS.Destination.ALLOW_ALL 
    # )

    # server_destination.register_request_handler(
    # "/phrase",
    # response_generator=lambda path, data, request_id, link_id, remote_identity, requested_at: iop_handlers.get_phrase_handler(None, path, data, request_id, link_id, remote_identity, requested_at),
    # allow=RNS.Destination.ALLOW_ALL
    # )

    # server_destination.register_request_handler(
    # "/get_hyd_vault",
    # response_generator=lambda path, data, request_id, link_id, remote_identity, requested_at: iop_handlers.get_hyd_vault_handler(None, path, data, request_id, link_id, remote_identity, requested_at),
    # allow=RNS.Destination.ALLOW_ALL
    # )

    # server_destination.register_request_handler(
    # "/get_morpheus_vault",
    # response_generator=lambda path, data, request_id, link_id, remote_identity, requested_at: iop_handlers.get_morpheus_vault_handler(None, path, data, request_id, link_id, remote_identity, requested_at),
    # allow=RNS.Destination.ALLOW_ALL
    # )

    # server_destination.register_request_handler(
    # "/get_new_acc_on_vault",
    # response_generator=lambda path, data, request_id, link_id, remote_identity, requested_at: iop_handlers.get_new_account_on_vault_handler(None, path, data, request_id, link_id, remote_identity, requested_at),
    # allow=RNS.Destination.ALLOW_ALL
    # )

    # server_destination.register_request_handler(
    # "/get_wallet",
    # response_generator=lambda path, data, request_id, link_id, remote_identity, requested_at: iop_handlers.get_wallet_handler(None, path, data, request_id, link_id, remote_identity, requested_at),
    # allow=RNS.Destination.ALLOW_ALL
    # )

    # server_destination.register_request_handler(
    # "/generate_did_by_morpheus",
    # response_generator=lambda path, data, request_id, link_id, remote_identity, requested_at: iop_handlers.generate_did_by_morpheus_handler(None, path, data, request_id, link_id, remote_identity, requested_at),
    # allow=RNS.Destination.ALLOW_ALL
    # )

    # server_destination.register_request_handler(
    # "/sign_witness_statement",
    # response_generator=lambda path, data, request_id, link_id, remote_identity, requested_at: iop_handlers.sign_witness_statement_handler(None, path, data, request_id, link_id, remote_identity, requested_at),
    # allow=RNS.Destination.ALLOW_ALL
    # )

    # server_destination.register_request_handler(
    # "/sign_did_statement",
    # response_generator=lambda path, data, request_id, link_id, remote_identity, requested_at: iop_handlers.sign_did_statement_handler(None, path, data, request_id, link_id, remote_identity, requested_at),
    # allow=RNS.Destination.ALLOW_ALL
    # )

    # server_destination.register_request_handler(
    # "/nonce",
    # response_generator=lambda path, data, request_id, link_id, remote_identity, requested_at: iop_handlers.get_nonce_handler(None, path, data, request_id, link_id, remote_identity, requested_at),
    # allow=RNS.Destination.ALLOW_ALL
    # )

    # server_destination.register_request_handler(
    # "/sign_transaction",
    # response_generator=lambda path, data, request_id, link_id, remote_identity, requested_at: iop_handlers.sign_transaction_handler(None, path, data, request_id, link_id, remote_identity, requested_at),
    # allow=RNS.Destination.ALLOW_ALL
    # )

    # Start server loop
    signal.signal(signal.SIGINT, signal_handler)
    server_loop(server_destination)

def server_loop(destination):
    RNS.log(f"Server running at {RNS.prettyhexrep(destination.hash)} waiting for connections")
    while True:
        try:
            entered = input()
            destination.announce()
            RNS.log(f"Sent announce from {RNS.prettyhexrep(destination.hash)}")

        except KeyboardInterrupt:
            RNS.log("KeyboardInterrupt detected. Exiting...")

        except Exception as e:
            RNS.log(f"Error: {str(e)}")
