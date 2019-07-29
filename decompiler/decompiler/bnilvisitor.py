from binaryninja import log_debug


class BNILVisitor(object):
    def __init__(self, **kw):
        super(BNILVisitor, self).__init__()

    def visit(self, expression):
        method_name = "visit_{}".format(expression.operation.name)
        if hasattr(self, method_name):
            value = getattr(self, method_name)(expression)
        else:
            print(f"{repr(expression.operation)}")
            value = None
        return value
