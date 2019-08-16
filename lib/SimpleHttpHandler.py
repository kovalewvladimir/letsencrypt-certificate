from logging.handlers import HTTPHandler


class SimpleHttpHandler(HTTPHandler):
    def __init__(self, no_date='false', **kwargs):
        HTTPHandler.__init__(self, **kwargs)
        self.no_date = no_date

    def mapLogRecord(self, record):
        """Map log record as required format of HTTP/HTTPS server"""
        record_modified = HTTPHandler.mapLogRecord(self, record)
        if self.formatter is not None:
            record_modified['t'] = self.formatter.format(record)
        else:
            record_modified['t'] = record_modified['msg'].encode('utf-8')

        record_modified['no_date'] = self.no_date
        return record_modified
