class EqmUserSession(object):
    """
    user session storage
    """
    def update(self, **kwargs):
        """
        Update __dict__ but only for keys that have been predefined
        (silently ignore others)
        :param kwargs: session vars
        """
        self.__dict__.update((key, value) for key, value in kwargs.items() if key in list(self.__dict__.keys()))

    def __init__(self, **kwargs):
        # default vars
        # End of response to successfully processed request.
        self.good_result = '+OK'
        # End of response to unsuccessfully processed request.
        self.bad_result = '-ERROR'
        self.user = None
        self.password = None
        self.app = None
        self.version = None
        self.required_filters = None
        self.desired_filters = None

        # default packet size for results sending in chunks
        self.packet_size = 5000
        self.local_ip = None
        self.local_port = None
        self.app_session_id = None
        self.db_conn = None

        self.update(**kwargs)

    def __del__(self):
        if self.db_conn:
            try:
                self.db_conn.close()
            except Exception as e:
                self.db_conn.debug(str(e))
