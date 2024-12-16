class Singleton(type):
    __singletons = {}
    def __call__(cls):
        singletons = Singleton.__singletons
        if cls not in singletons:
            inst = singletons[cls] = super(Singleton, cls).__call__()
            return inst
        return singletons[cls]
