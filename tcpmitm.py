import sys
import pprint
import socket
import threading
import Queue

class SendableMessage():
    def __init__(self, sendMessage, sock, message):
        self.sock = sock
        self.message = message
        self.sendMessage = sendMessage

    def send(self):
        self.sendMessage(self.sock, self.message)


class CleanupNotification():
    def __init__(self):
    	return
        


class TcpMitm():

    def __init__(self, extension, lHost, lPort, rHost, rPort, bufSize):
        self.extension = extension
        self.lHost = lHost
        self.lPort = lPort
        self.rHost = rHost
        self.rPort = rPort
        self.lSock = None
        self.rSock = None
        self.bufSize = bufSize
        self.lListenThread = None
        self.lSendThread = None
        self.rListenThread = None
        self.rSendThread = None
        self.rThread = None
        self.lMessageSendQueue = Queue.Queue()
        self.rMessageSendQueue = Queue.Queue()
        self.threadRestartLock = threading.Lock()

    #def sockAcceptListenRun(self, sock, queue):
    #    conn, addr = sock.accept()
    #    sockListenRun(conn, queue):

    def sockListenRun(self, sock, queue):
        # works on a "message" view. With no modifications, "messages" are TCP stream reads.
        # implement custom parsing in sendMessage/recvMessage
        while True:
            m = self.recvMessage(sock)
            print("got m in socklistenrun:"); sys.stdout.flush()
            print(m); sys.stdout.flush()
            print(len(m)); sys.stdout.flush()
            if(len(m)):
                print('storing message:'); sys.stdout.flush()
                print(m)
                queue.put(m)
            else:
                print('shutting down sock'); sys.stdout.flush()
                # client has closed connection. We should close the upstream connection too! (rSock)
                break
        

    def sockSendRun(self, sock, queue):
        while True:
            m = queue.get()
            if isinstance(m, CleanupNotification):
                # time to clean up, this was the sentinel message sent to make sure
                # the thread doesn't hang at queue.get(). We can assume the socket
                # has already been closed by the creator of the cleanup notification
                print("got a cleanup notification in socksendrun"); sys.stdout.flush()
                return
            print("got m in socksendrun:"); sys.stdout.flush()
            print(m)
            print("current interception status:"); sys.stdout.flush()
            print(self.extension.intercept)
            if self.extension.intercept:
                print("creating SendableMessage with message:"); sys.stdout.flush()
                sm = SendableMessage(self.sendMessage, sock, m)
                print(sm.message)
                self.extension.addToQueue(sm)#mainMessageQueue.put(SendableMessage(sock,m))
                print("done with addToQueue call"); sys.stdout.flush()
            else:
                self.sendMessage(sock, m)

    def sendMessage(self, s, message):
        # this is where custom message sending logic should go
        s.sendall(message)

    def recvMessage(self, s):
        # this is where custom message recv logic should go
        m = s.recv(self.bufSize)
        return m 

    def stop(self):
        self.lSock.close()
        self.rSock.close()
        print("stopping TcpMitm!")

    def manageLThreads(self):
        print("listening on lSock(%s:%d) for connection" % (self.lHost, self.lPort))
        sys.stdout.flush()
        while True:
            self.conn, addr = self.lSock.accept()
            print("got a connection!"); sys.stdout.flush()
            self.lListenThread = threading.Thread(target=self.sockListenRun, args=(self.conn, self.rMessageSendQueue))
            print("created llisten"); sys.stdout.flush()
            self.lSendThread = threading.Thread(target=self.sockSendRun, args=(self.conn, self.lMessageSendQueue))
            print("created lsend"); sys.stdout.flush()

            self.lListenThread.start()
            self.lSendThread.start()
            print("Started lsend and llisten"); sys.stdout.flush()
            self.lListenThread.join()
            print("joined llisten"); sys.stdout.flush()
            conn.close()

            # throws a message into the queue just to ensure that lSendThread terminates
            self.lMessageSendQueue.put(CleanupNotification())
            self.lSendThread.join()
            # client disconnected, we should disconnect from the remote client as well
            self.rSock.close()
            # sync up the restart so neither thread closes a new socket by mistake
            self.threadRestartLock.acquire()
            self.threadRestartLock.wait()
            self.threadRestartLock.release()

    def manageRThreads(self):
        while True:
            self.rSock.connect((self.rHost, self.rPort))
            self.rListenThread = threading.Thread(target=self.sockListenRun, args=(self.rSock, self.lMessageSendQueue))
            self.rSendThread = threading.Thread(target=self.sockSendRun, args=(self.rSock, self.rMessageSendQueue))

            self.rListenThread.start()
            self.rSendThread.start()
            print("Started rsend and rlisten")
            self.rListenThread.join()
            print("joined llisten")
            self.rSock.close()
            # throws a message into the queue just to ensure that lSendThread terminates
            self.rMessageSendQueue.put(CleanupNotification())
            self.rSendThread.join()
            # client disconnected, we should disconnect from the remote client as well
            self.rSock.close()
            # sync up the restart so neither thread closes a new socket by mistake
            self.threadRestartLock.acquire()
            self.threadRestartLock.notify()
            self.threadRestartLock.release()


    def start(self):
        self.lSock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.lSock.bind((self.lHost, self.lPort))
        self.lSock.listen(5)
        # blocking

        self.rSock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

        self.manageLThreads = threading.Thread(target=self.manageLThreads)
        self.manageLThreads.start()

        self.manageRThreads = threading.Thread(target=self.manageRThreads)
        self.manageRThreads.start()
    
        print("created lSock(%s:%d) -> rSock(%s:%d) TcpMitm" % (self.lHost, self.lPort, self.rHost, self.rPort))
        return None

