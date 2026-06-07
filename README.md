## reverse-proxy

An asynchronous, multi-threaded reverse proxy (for both Windows & Linux), designed to efficiently handle thousands of concurrent connections. Features include per-client rate limiting to mitigate application layer attacks and built-in TLS support (with session caching) for secure, high-performance communication.

## Features

- **Asynchronous I/O:** Uses IOCP (I/O Completion Ports) for scalable, non-blocking networking.
- **Multi-threaded:** Worker thread pool for efficient event handling.
- **TLS Termination:** Secure connections with OpenSSL, including session caching for fast resumption.
- **Per-client IP Rate Limiting:** Prevents abuse and application-layer attacks.
- **Load Balancing:** Intelligent request distribution across multiple backend servers with multiple algorithms (Round Robin, Least Connections, Weighted Round Robin, IP Hash, Random). Route-based pool management for different services.
- **Connection Management:** Robust handling of thousands of concurrent sockets.

### Workflow 1 - read from client and send to upstream
To achieve maximum network throughput without data corruption, the client-to-upstream data flow operates under a strict producer-consumer model with a single connection-specific mutex lock.
For each client connection, it is ensured that only at most one WSARecv call is pending at any time so that the data from client is processed in the same order as received. When data arrives, a single worker thread from the pool is awakened by IOCP. This thread performs the necessary application logic such as rate limiting and load balancing. Then, it acquires a lock to put data into the buffer and send it to upstream if no send if pending.
Once the send is completed, a thread is awakened which acquires the mutex, sets the isSendBusy (a boolean to track if any send to upstream is pending) to false, starts a new send, sets isSendBusy to true and releases the lock.
The mutex helps us to solve the producer-consumer problem by granting access of the buffer to only one thread.
<img width="1736" height="914" alt="workflow1-reverseproxy" src="https://github.com/user-attachments/assets/75b000ab-07c2-4388-b45f-352943ba6c3f" />
#### Potential Deadlock Scenario and How this Architecture solves it
One important point to note from the workflow is that any update to the boolean flag ***isSendBusy*** must always occur after the thread has acquired the mutex. Without this the following situation can occur:
```
Thread A                                 Thread B
aquire mutex.lock()                      isSendBusy = false
     # critical section                  acquire mutex.lock()
     if (!isSendBusy):                    if (!buffer.empty()):
        copy to buffer                       post send
        post send                            isSendBusy = true
        isSendBusy = true                else:
     else:                                   do nothing 
        copy to buffer                   release mutex.lock()
release mutex.lock()
```
Consider that client just sent data (buffer is empty) and Thread B acquired the lock before Thread A. In the above scenario, due to CPU memory order operations, the isSendBusy = false might not complete until after the lock is released in Thread B. This means the thread B does nothing and releases the lock. But just before thread B sets isSendBusy to false, Thread A might acquire the lock and read the isSendBusy value (which is still True). Then, Thread A just copies to buffer and releases the lock. <p>
Now, the buffer has some data and isSendBusy is false, which means that only way the data in the buffer will be sent to upstream is if client sends data again and awakens Thread A logic. If not, the data remains in buffer and not get sent to upstream server and client keeps waiting for server's response to send new data. This results in a deadlock. <p>
Therefore, any update to the isSendBusy must occur after acquiring the lock and before realeasing as shown in the workflow diagram and as followed in the project.


### System Architecture And Workflow

```mermaid
flowchart TB
    %% =========================
    %% EXTERNAL
    %% =========================
    Client["Client"]
    style Client fill:#e3f2fd,stroke:#1976d2,stroke-width:2px

    %% =========================
    %% ACCEPT LAYER
    %% =========================
    subgraph AcceptLayer["Accept Layer"]
        Listen["Listening Socket"]
        Accept["Accept New Connection"]
        AcceptBuf["Address Buffer"]
    end
    style AcceptLayer fill:#fffde7,stroke:#fbc02d,stroke-width:2px

    %% =========================
    %% IOCP CORE
    %% =========================
    subgraph IOCP_Core["IOCP Core"]
        IOCP["Completion Port"]
        CQ["Completion Queue"]
    end
    style IOCP_Core fill:#e1f5fe,stroke:#0288d1,stroke-width:2px

    %% =========================
    %% WORKERS
    %% =========================
    subgraph Workers["Worker Threads"]
        GQCS["Wait for Events"]
        Dispatch["Handle Event Type"]
    end
    style Workers fill:#e8f5e9,stroke:#43a047,stroke-width:2px

    %% =========================
    %% CONNECTION STATE
    %% =========================
    subgraph ConnState["Connection State"]
        Sock["Socket"]
        PendingIO["Pending Operations"]
        Closing["Closing Flag"]
        ClientIP["Client IP"]
        TLSConn["TLS State"]
    end
    style ConnState fill:#ede7f6,stroke:#7e57c2,stroke-width:2px

    %% =========================
    %% RATE LIMITING
    %% =========================
    subgraph RateLimit["Rate Limiting"]
        RLAccept["Check at Accept"]
        RLApp["Check on Data"]
    end
    style RateLimit fill:#fff3e0,stroke:#f57c00,stroke-width:2px

    %% =========================
    %% TLS PIPELINE
    %% =========================
    subgraph TLS["TLS Processing"]
        Handshake["Handshake"]
        Decrypt["Decrypt Data"]
        Encrypt["Encrypt Data"]
        TLSBuf["TLS Output Buffer"]
    end
    style TLS fill:#e0f7fa,stroke:#00acc1,stroke-width:2px

    %% =========================
    %% ASYNC IO
    %% =========================
    subgraph AsyncIO["Async I/O"]
        PostRecv["Receive Data"]
        PostSend["Send Data"]
    end
    style AsyncIO fill:#fce4ec,stroke:#d81b60,stroke-width:2px

    %% =========================
    %% FLOW
    %% =========================
    Client -->|Connect| Listen
    Listen --> Accept
    Accept --> AcceptBuf
    Accept -->|Ready| IOCP
    IOCP --> CQ
    CQ --> GQCS
    GQCS --> Dispatch

    %% OP_ACCEPT workflow
    Dispatch -->|Accept Event| RLAccept
    RLAccept -->|Allowed| ConnState
    RLAccept -->|Rejected| Client
    ConnState -->|Register| IOCP
    ConnState -->|Start| PostRecv

    %% OP_READ workflow
    Dispatch -->|Read Event| Handshake
    Handshake -->|If Complete| Decrypt
    Decrypt -->|Plain Data| RLApp
    RLApp -->|Allowed| Encrypt
    RLApp -->|Rate Limited| Encrypt
    Encrypt --> TLSBuf
    TLSBuf --> PostSend

    %% OP_WRITE workflow
    Dispatch -->|Write Event| PendingIO
    PendingIO -->|If Done & Closing| Closing
    Closing -->|Cleanup| Sock
```



**Starting the Proxy:**

```bash
make clean
```
```bash
make
```
```bash
./main.exe
```

## License

MIT License
