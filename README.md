# 스마트 네트워크 서비스 AD과제

## 팀14
학번:20213051 이름:이재준 / 학번:20213049 이름:이재영


---

# ▶️ 실행 방법

터미널을 먼저 실행시킨 뒤 smart_net_suite_skeleton.py가 있는 위치로 이동한 후
## 📍 macOS/unix
```bash
python3 smart_net_suite_skeleton.py
```
## 📍 Window
```bash
python smart_net_suite_skeleton.py
```
저는 macOS에서 진행하였습니다.

# 📊 16개 요구사항 체크리스트

| 번호 | 요구사항 | 상태 |
|------|-----------|-------|
| 1 | IP 구성 확인 | ✔️ |
| 2 | 바이트 정렬 hton/ntoh | ✔️ |
| 3 | IP 변환 pton/ntop | ✔️ |
| 4 | DNS/역방향 조회 | ✔️ |
| 5 | 포트 검사 | ✔️ |
| 6 | netstat 필터 | ✔️ |
| 7 | TCP 서버 상태 표시 | ✔️ |
| 8 | TCP 클라이언트 | ✔️ |
| 9 | 소켓 버퍼 조회 | ✔️ |
| 10 | 네트워크 그림판 | ✔️ |
| 11 | FIXED 전송 | ✔️ |
| 12 | VAR 전송 | ✔️ |
| 13 | MIX 전송 | ✔️ |
| 14 | 전송 후 종료 | ✔️ |
| 15 | Lock(임계영역) | ✔️ |
| 16 | Event(안전 종료) | ✔️ |

# 1. IP 구성 확인

## 실행결과
<img width="1432" height="753" alt="스크린샷 2025-12-10 오전 10 09 11" src="https://github.com/user-attachments/assets/15e8bc71-ca74-4e33-a99c-fca5226ec0c7" />
터미널에서 ifconfig -a 명령을 실행했을 때와 비교해보면 ip 구성 확인을 눌렀을 때 결과가 같은 것을 확인할 수 있습니다.

## do_ipconfig
```bash
    def do_ipconfig(self):
        pc_os = self.pc_os
        command = "ifconfig -a"

        if (pc_os == "Windows"): command = "ipconfig /all"

        pipe = os.popen(command)
        output = pipe.read()
        pipe.close()

        target = {"diag": self.out_diag, "sfc": self.out_sfc}.get("diag", None)
        self._append(target, f"$ {command}\n{output}")
```
사용자 os를 먼저 인식한 뒤 os에 맞게 IP 구성을 확인하는 명령을 실행시켜줍니다.

# 2. 바이트 정렬 함수

## 실행결과
<img width="572" height="110" alt="스크린샷 2025-12-10 오전 10 20 20" src="https://github.com/user-attachments/assets/4925baf3-3c11-4995-8275-9c038914f751" />

네트워크 진단 탭에서 바이트/주소 변환의 hton/ntoh 데모를 클릭한 결과입니다.
16비트, 32비트, 64비트에서 변환/역변환이 올바르게 일어나고 있는 것을 눈으로 확인할 수 있습니다.

## do_hton
```bash
    def do_hton(self):
        self._append(self.out_diag, "---------[hton/ntoh 데모]---------")

        # 16 비트
        v16 = 0x1234
        net16 = socket.htons(v16)
        host16 = socket.ntohs(net16)
        self._append(self.out_diag, f"16bit host=0x{v16:04X} -> network=0x{net16:04X} -> host=0x{host16:04X}")

        # 32비트
        v32 = 0x12345678
        net32 = socket.htonl(v32)
        host32 = socket.ntohl(net32)
        self._append(self.out_diag, f"32bit host=0x{v32:08X} -> network=0x{net32:08X} -> host=0x{host32:08X}")

        # 64비트 (struct 이용)
        v64 = 0x0123456789ABCDEF

        host_bytes = struct.pack("=Q", v64)
        net_bytes = struct.pack("!Q", v64)

        swapped = int.from_bytes(net_bytes, byteorder='little')

        self._append(self.out_diag, f"64bit host=0x{v64:016X}")
        self._append(self.out_diag, f"      host bytes (native endian)     = {host_bytes.hex()}")
        self._append(self.out_diag, f"      network bytes (big-endian)     = {net_bytes.hex()}")
        self._append(self.out_diag, f"      network->little endian swap    = 0x{swapped:016X}")
        self._append(self.out_diag, "-------------------------------------")
```
16비트에서는 socket.htons, socket.ntohs
32비트에서는 socket.htonl, socket.ntohl
64비트에서는 struct를 이용하여 다음과 같은 실행화면이 나올 수 있게 하였습니다.

# 3. IP 변환 pton/ntop

## IPv4/IPv6실행결과
<img width="573" height="211" alt="스크린샷 2025-12-10 오전 10 59 07" src="https://github.com/user-attachments/assets/ad9d3efd-f37b-4197-b9bd-51fca5a6b770" />

8.8.8.8과 6.6.6.6에 대한 pton/ntop가 잘 이루어진 것을 확인할 수 있습니다.

2001:4860:4860::8888과 1001:1001:1001::1001에 대한 pton/ntop 변환이 잘 이루어진 것을 확인할 수 있습니다.
다만 2001:4860:4860::8888 pton 앞부분에서 H와 같이 문자로 나타는 것은
바이트 값 자체가 문자로 표현될 수 있으면 Python은 그걸 repr에 포함해서 보기 조금 이상한 형태가 되는 것입니다.

## do_inet4/do_inet6
```bash
    def do_inet4(self):
        demo_ipv4 = self.var_ipv4.get()

        target = {"diag": self.out_diag, "sfc": self.out_sfc}.get("diag", None)

        self._append(target, "---------IPv4 (AF_INET)---------")
        ipv4_bin = socket.inet_pton(socket.AF_INET, demo_ipv4)
        self._append(target, f"pton : {ipv4_bin!r}")

        ipv4_str_converted = socket.inet_ntop(socket.AF_INET, ipv4_bin)
        self._append(target, f"ntop : '{ipv4_str_converted}'")
        self._append(target, "--------------------------------")

    def do_inet6(self):
        demo_ipv6 = self.var_ipv6.get()

        target = {"diag": self.out_diag, "sfc": self.out_sfc}.get("diag", None)

        self._append(target, "---------IPv6 (AF_INET6)---------")
        ipv6_bin = socket.inet_pton(socket.AF_INET6, demo_ipv6)
        self._append(target, f"pton : {ipv6_bin!r}")

        ipv6_str_converted = socket.inet_ntop(socket.AF_INET6, ipv6_bin)
        self._append(target, f"ntop : '{ipv6_str_converted}'")
        self._append(target, "--------------------------------")
```
ipv4와 ipv6에 해당하는 문자열을 가져와서 inet_pton / inet_ntop를 이용하여 출력했습니다.

# 4. DNS/역방향 조회

## DNS/역방향 실행결과
<img width="1361" height="751" alt="스크린샷 2025-12-10 오전 11 11 19" src="https://github.com/user-attachments/assets/c975c079-7c5b-4a23-a0d3-631d82b4ee62" />

example.com과 8.8.8.8에 대한 DNS/역방향 버튼을 클릭했을 때의 결과와 터미널에서 nslookup을 통해 조회한 두 항목에 대한 결과가 같음을 통해 잘 실행되는 것을 확인할 수 있습니다.

## do_dns/do_reverse
```bash
    def do_dns(self):
        hostname = self.var_dns.get()
        command = f'nslookup {hostname}'

        pipe = os.popen(command)
        output = pipe.read()
        pipe.close()

        target = {"diag": self.out_diag, "sfc": self.out_sfc}.get("diag", None)
        self._append(target, f"$ {command}\n{output}")

    def do_reverse(self):
        hostname = self.var_rev.get()
        command = f'nslookup {hostname}'

        pipe = os.popen(command)
        output = pipe.read()
        pipe.close()

        target = {"diag": self.out_diag, "sfc": self.out_sfc}.get("diag", None)
        self._append(target, f"$ {command}\n{output}")
```
nslookup에 대한 동작은 OS마다 동일하여 따로 나눠줄 필요없고 GUI 입력값을 불러와 터미널에서 실행시킨 값을 가져오는 형태로 작성하였습니다.

# 5,6. Server 상태 확인 / netstat

## 포트 오픈 여부 검사/netstat
<img width="1422" height="799" alt="스크린샷 2025-12-10 오전 11 58 48" src="https://github.com/user-attachments/assets/cd5b8cd4-d591-4dae-b0eb-c8f953f53fec" />

서버를 가동시키지 않았을 때 포트 스캔과 netstat을 하여도 is not open과 아무런 결과가 나오지 않는데
서버를 가동시킨 뒤 버튼을 눌렀을 때 is open과 netstat을 통해 listen 상태에 있는 것을 확인할 수 있습니다.
<img width="907" height="50" alt="스크린샷 2025-12-10 오후 12 00 24" src="https://github.com/user-attachments/assets/938a6f4f-16f9-410f-876a-868cc14f32de" />

클라이언트를 가동한 후 다시 netstat을 한 결과 established 된 것을 볼 수 있습니다.

## do_check_port/do_netstat
```bash
    def do_netstat(self):
        pc_os = self.pc_os
        port = self.var_netstat.get()
        command = f"netstat -a -n -p tcp | grep {port}"

        if (pc_os == "Windows"): command = f"netstat -a -n -p tcp | findstr {port}"

        pipe = os.popen(command)
        output = pipe.read()
        pipe.close()

        target = {"diag": self.out_diag, "sfc": self.out_sfc}.get("diag", None)
        self._append(target, f"$ {command}{output}")

    def do_check_port(self):
        result = None
        ip = self.var_host.get()
        port = self.var_port.get()

        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(1.0)

        try:
            # 연결
            s.connect((ip, int(port)))
            result = True

        except socket.timeout:
            # 연결 시간 초과
            result = False

        except socket.error as e:
            # 연결 거부
            result = False

        finally:
            # 소켓 닫기
            s.close()

        target = {"diag": self.out_diag, "sfc": self.out_sfc}.get("diag", None)
        if (result):
            self._append(target, f"{ip}:{port} is open")
        else:
            self._append(target, f"{ip}:{port} is not open")
```
먼저 netstat에서는 os를 먼저 판별하고 os 별로 다른 명령어를 구성했습니다. os쉘을 통해 명령어를 실행하고 결과를 출력하도록 하였습니다.
netstat은 os가 제공하는 표만 출력하기 때문에 실제로 TCP 소켓을 만들어 연결을 시도해야합니다.
IPv4 TCP 소켓을 생성하였고 1초동안만 연결을 시도하고 응답 없으면 timeout이 되게 하였습니다.
연결에 성공하면 포트가 열려있는 것으로 result = True로 하였고 서버가 해당 포트에서 리스닝하지 않으면 result = False로 하였습니다. 
마지막으로 socket을 닫고 GUI에 띄워줬습니다.

# 7,8 GUI TCP SERVER/CLIENT 함수 상태 표시

## 서버 시작
<img width="1092" height="741" alt="스크린샷 2025-12-10 오후 12 08 50" src="https://github.com/user-attachments/assets/de14e89d-4971-40b8-acb0-1acdb76f62fd" />

## 클라이언트 접속
<img width="1091" height="737" alt="스크린샷 2025-12-10 오후 12 09 19" src="https://github.com/user-attachments/assets/85977580-13cb-48e8-b4aa-e6bd9ce38e82" />

## 클라이언트 접속해제
<img width="1094" height="744" alt="스크린샷 2025-12-10 오후 12 11 07" src="https://github.com/user-attachments/assets/323a6db2-3bd7-4109-834a-f24918213bd1" />

## 상태 갱신 및 서버 정지 
<img width="1091" height="744" alt="스크린샷 2025-12-10 오후 12 11 22" src="https://github.com/user-attachments/assets/01461e85-e95c-40d2-a929-9a434affb478" />

<img width="907" height="50" alt="스크린샷 2025-12-10 오후 12 00 24" src="https://github.com/user-attachments/assets/938a6f4f-16f9-410f-876a-868cc14f32de" />

위 과정을 통해서 TCP SERVER/CLIENT 함수 상태 표시가 원활하게 일어난다는 것을 확인할 수 있습니다.

## TCP Server
```bash
    def server_start(self):
        if self.server_running:
            return

        # 이전 종료 신호 초기화
        self.stop_event.clear()
        self.server_running = True

        port = int(self.var_srv_port.get())
        # TODO: 소켓 생성/리스닝/스레드 시작

        # 소켓 생성 (IPv4, TCP)
        try:
            self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        except socket.error as e:
            self.log_srv(f"[오류] 소켓 생성 실패: {e}")
            self.server_running = False
            return

        # 포트 재사용 설정
        self.server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

        # 바인딩 (IP 주소와 포트 연결)
        try:
            self.server_socket.bind(('', port))
        except socket.error as e:
            self.log_srv(f"[오류] 포트 바인딩 실패: 포트 {port} 사용 중. {e}")
            self.server_running = False
            self.server_socket.close()
            return

        # 리스닝 (클라이언트 연결 대기 모드)
        try:
            self.server_socket.listen(5)
            self.log_srv(f"[성공] 서버 리스닝 시작 (Port: {port})")
        except socket.error as e:
            self.log_srv(f"[오류] 리스닝 실패: {e}")
            self.server_running = False
            self.server_socket.close()
            return

        # 메인 서버 루프 스레드 시작
        self.accept_thread = threading.Thread(target=self._accept_connections)
        self.accept_thread.daemon = True
        self.accept_thread.start()

        self.log_srv("[정보] 연결 수락 스레드 시작 완료.")

    def _accept_connections(self):
        while self.server_running:
            try:
                client_socket, addr = self.server_socket.accept()
                self.log_srv(f"[연결] 클라이언트 접속: {addr[0]}:{addr[1]}")

                with self.status_lock:
                    self.active_clients.append(client_socket)
                    self.client_counter += 1

                client_thread = threading.Thread(target=self._handle_client, args=(client_socket, addr))
                client_thread.daemon = True
                self.client_threads.append(client_thread)
                client_thread.start()

            except socket.error as e:
                if self.server_running:
                    # 서버가 닫히지 않았는데 오류 발생
                    self.log_srv(f"[오류] 연결 수락 중 오류 발생: {e}")
                break  # 오류 발생 시 루프 종료

        # 서버 종료 시 소켓 정리
        try:
            self.server_socket.close()
        except:
            pass

        self.log_srv("[서버] 연결 수락 스레드 종료됨.")

    def _handle_client(self, client_socket, addr):
        try:
            client_socket.sendall(b"Welcome to the Skeleton Server!\n")

            while not self.stop_event.is_set():
                try:
                    data = client_socket.recv(1024)
                except OSError as e:
                    # 서버가 끄는 중이면 정보 로그로만
                    if self.stop_event.is_set():
                        self.log_srv(f"[정보] 서버 종료 중 recv 중단: {addr[0]}:{addr[1]}")
                    else:
                        self.log_srv(f"[오류] 클라이언트 {addr[0]}:{addr[1]} 처리 중 오류: {e}")
                    break

                if not data:
                    # 클라이언트가 정상적으로 연결 종료
                    break

                # 그림판 패킷 브로드캐스트
                if len(data) == 16 and self.var_broadcast.get():
                    self._broadcast(data, exclude=client_socket)
                    continue

                # FIXED
                if len(data) == 32:
                    text = data.decode('utf-8', errors='ignore')
                    self.log_srv(f"[FIXED 수신] {addr[0]}:{addr[1]} len={len(data)} → '{text}'")
                    continue

                # VAR
                if b'\n' in data:
                    for line in data.split(b'\n'):
                        if not line:
                            continue
                        text = line.decode('utf-8', errors='ignore')
                        self.log_srv(f"[VAR 수신] {addr[0]}:{addr[1]} → '{text}'")
                    continue

                # MIX
                if len(data) >= 4:
                    header = data[:4]
                    msg_len = struct.unpack('!I', header)[0]

                    payload = data[4:4 + msg_len]

                    text = payload.decode('utf-8', errors='ignore')
                    self.log_srv(
                        f"[MIX 수신] {addr[0]}:{addr[1]} len={msg_len}, 실제={len(payload)} → '{text}'"
                    )
                    continue

                message = data.decode('utf-8', errors='ignore').strip()
                self.log_srv(f"[수신] {addr[0]}:{addr[1]} ← {message}")

        finally:
            self.log_srv(f"[종료] 클라이언트 연결 해제: {addr[0]}:{addr[1]}")
            with self.status_lock:
                if client_socket in self.active_clients:
                    self.active_clients.remove(client_socket)
            try:
                client_socket.close()
            except OSError:
                pass

    def _broadcast(self, data, exclude=None):
        with self.status_lock:
            targets = list(self.active_clients)
        for cs in targets:
            if cs is exclude:  # 보내온 클라 제외
                continue
            try:
                cs.sendall(data)
            except Exception as e:
                print("[ERROR] 브로드캐스트 실패:", e)

    def server_stop(self):
        if not self.server_running:
            return

        # TODO: stop event, join
        self.stop_event.set()
        self.server_running = False

        if hasattr(self, 'server_socket') and self.server_socket:
            try:
                self.server_socket.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass  # 소켓이 이미 닫혀 있거나 연결이 없는 경우 무시
            except Exception as e:
                self.log_srv(f"[경고] shutdown 중 오류 발생: {e}")

            try:
                self.server_socket.close()
                self.log_srv("[정보] 서버 리스닝 소켓 강제 종료 완료.")
            except Exception as e:
                self.log_srv(f"[경고] close 중 오류 발생: {e}")

        with self.status_lock:
            clients = list(self.active_clients)
            self.active_clients.clear()

        for cs in clients:
            try:
                cs.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass
            except Exception as e:
                self.log_srv(f"[경고] 클라이언트 shutdown 중 오류: {e}")
            try:
                cs.close()
            except Exception as e:
                self.log_srv(f"[경고] 클라이언트 close 중 오류: {e}")

        # 연결 수락 스레드 종료 대기 (Join)
        if hasattr(self, 'accept_thread') and self.accept_thread.is_alive():
            self.accept_thread.join(timeout=1.0)
            self.log_srv("[정보] 연결 수락 스레드 종료 대기 완료.")

        for th in list(self.client_threads):
            try:
                if th.is_alive():
                    th.join(timeout=1)
            except:
                pass
        self.client_threads.clear()

        self.log_srv("[서버] 정지 완료.")

    def server_status(self):
        # TODO: 실제 접속 수/카운터 반영
        current_clients = 0
        total_counter = 0

        with self.status_lock:
            current_clients = len(self.active_clients)
            total_counter = self.client_counter

        try:
            # TODO: 실제 접속 수/카운터 반영
            self.lbl_clients.config(text=f"접속: {current_clients}")
            self.lbl_counter.config(text=f"카운터: {total_counter}")
            self.log_srv("[서버] 상태 갱신 완료.")
        except Exception as e:
            self.log_srv(f"[오류] GUI 업데이트 실패: {e}")
```

TCP server를 먼저 살펴보자면 Start/Stop 버튼을 통해 TCP 서버 소켓을 생성하고 리스닝을 시작합니다.
또한 모든 스레드와 소켓을 안정적으로 종료하기 위해 threading.Event()를 이용해 종료 신호를 보냅니다.
리스닝 소켓, 클라이언트 소켓, 클라이언트 스레드를 순차적으로 종료하면서 리소스 누수 없게 만듭니다.
접속 수와 누적 접속 카운터는 server_status함수에서 업데이트되며, 공유 변수 보호를 위해 threading.Lock(status_lock)으로 감싸서 임계영역을 구성합니다.
서버 로그를 통해 서버 시작/정지 상태 클라이언트 접속/해제 클라이언트와 메세지 수신 결과등을 확인할 수 있습니다.
Accept Thread는 새로운 클라이언트 연결을 감지하여 처리 스레드를 생성하고, 
Client Threads는 각 클라이어은트의 수신 루프를 담당하고, 
GUI 스레드를 통해서 서버 스레드와 충돌 없이 상태 갱신을 수행합니다.
서버 종료는 stop_event로 제어됩니다.

## TCP client
```bash
    def cli_connect(self):
        # TODO: socket connect + recv 루프
        if self.client_connected:
            self.log_cli("[경고] 이미 서버에 연결되어 있습니다. 연결을 끊어주세요.")
            return

        host = self.var_cli_host.get()
        port = int(self.var_cli_port.get())

        self.log_cli(f"[클라] 연결 시도 → {host}:{port}")

        # 소켓 생성 (IPv4, TCP)
        try:
            self.client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        except socket.error as e:
            self.log_cli(f"[오류] 소켓 생성 실패: {e}")
            return

        # 서버에 연결 시도
        try:
            self.client_socket.connect((host, port))
            self.client_connected = True
            self.log_cli(f"[성공] 서버 연결 완료: {host}:{port}")

        except socket.error as e:
            self.log_cli(f"[오류] 연결 실패: 서버에 접속할 수 없습니다. {e}")
            self.client_socket.close()
            return

        # 데이터 수신(recv) 루프 스레드 시작
        self.recv_thread = threading.Thread(target=self._recv_loop)
        self.recv_thread.daemon = True  # 메인 프로그램 종료 시 스레드도 종료되도록 설정
        self.recv_thread.start()

        self.log_cli("[정보] 수신(Recv) 스레드 시작 완료.")

    def _recv_loop(self):
        # 연결이 유지되는 동안 반복
        while self.client_connected:
            try:
                data = self.client_socket.recv(1024)

                if not data:
                    self.log_cli("[종료] 서버가 연결을 닫았습니다.")
                    break

                if len(data) == 16 and self.var_broadcast.get():
                    x1, y1, x2, y2 = struct.unpack("!IIII", data)
                    self.log_cli(f"[수신: Draw] ← ({x1},{y1}) -> ({x2},{y2})")
                    self.canvas.create_line(x1, y1, x2, y2)
                    continue

                message = data.decode('utf-8', errors='ignore').strip()
                self.log_cli(f"[수신] ← {message}")

            except socket.error as e:
                # 연결이 끊어졌거나 다른 소켓 오류 발생
                if self.client_connected:
                    self.log_cli(f"[오류] 수신 중 오류 발생: {e}")
                break
            except Exception as e:
                self.log_cli(f"[예외] 예상치 못한 오류: {e}")
                break

        # 루프 종료 후 정리 작업
        self.client_connected = False
        if self.client_socket:
            try:
                self.client_socket.close()
                self.log_cli("[정보] 클라이언트 소켓 정리 완료.")
            except:
                pass

    def cli_close(self):
        # TODO: close

        if not self.client_connected:
            self.log_cli("[경고] 서버에 연결되어 있지 않습니다.")
            return

        self.client_connected = False
        self.log_cli("[클라] 연결 해제")

        # 소켓 닫기
        if hasattr(self, 'client_socket') and self.client_socket:
            try:
                self.client_socket.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass  # 이미 연결이 끊어졌거나 닫힌 경우 무시
            except Exception as e:
                self.log_cli(f"[경고] shutdown 중 오류 발생: {e}")

            try:
                self.client_socket.close()
                self.log_cli("[정보] 클라이언트 소켓 닫기 완료.")
            except Exception as e:
                self.log_cli(f"[경고] close 중 오류 발생: {e}")

        time.sleep(0.05)

        # 수신 스레드 종료 대기 (Join)
        if hasattr(self, 'recv_thread') and self.recv_thread and self.recv_thread.is_alive():
            self.recv_thread.join(timeout=1.0)
            self.log_cli("[정보] 수신 스레드 종료 대기 완료.")

        self.log_cli("[클라] 연결 해제 완료.")

    def cli_send(self):
        # TODO: VAR/FIXED/MIX 전송 구현
        if not self.client_connected:
            self.log_cli("[경고] 서버에 연결되어 있지 않아 메시지를 전송할 수 없습니다.")
            return

        mode = self.var_mode.get()
        raw_message = self.var_msg.get()
        atfer_close = self.var_after_close.get()

        self.log_cli(f"[클라] 모드={mode} 메시지='{raw_message}'")

        data_bytes = raw_message.encode('utf-8')
        data_length = len(data_bytes)

        try:
            if mode == "FIXED":
                FIXED_SIZE = 32

                # 버퍼 생성 및 데이터 채우기
                if data_length > FIXED_SIZE:
                    self.log_cli(f"[오류] FIXED 모드: 메시지 길이가 {FIXED_SIZE}바이트를 초과하여 전송 불가.")
                    return

                # 메시지를 담고 남은 공간은 널(0) 바이트로 채움
                padded_data = data_bytes.ljust(FIXED_SIZE, b'\0')

                self.client_socket.sendall(padded_data)
                self.log_cli(f"[전송] FIXED: {data_length}바이트 메시지 + 패딩 ({FIXED_SIZE}바이트 전송)")

            elif mode == "VAR":
                packet = data_bytes + b'\n'
                self.client_socket.sendall(packet)
                self.log_cli(f"[전송] VAR: 메시지 {len(data_bytes)}B + '\\n' (총 {len(packet)}B)")

            elif mode == "MIX":
                header = struct.pack('!I', len(data_bytes))
                packet = header + data_bytes
                self.client_socket.sendall(packet)
                self.log_cli(f"[전송] MIX: 헤더 4B + 메시지 {len(data_bytes)}B (총 {len(packet)}B)")

            else:
                self.log_cli(f"[오류] 알 수 없는 전송 모드: {mode}")

            if atfer_close:
                self.cli_close()

        except socket.error as e:
            self.log_cli(f"[오류] 데이터 전송 실패: 연결 오류 발생. {e}")

        except Exception as e:
            self.log_cli(f"[예외] 데이터 전송 중 예상치 못한 오류: {e}")
```

TCP Client는 Cli_connect를 이용하여 중복연결을 방지하고 입력된 호스트/포트 값을 가져와서 소켓을 생성하고 연결을 시도합니다.
별도로 수신 스레드를 만들어 _recv_loop()를 통해 GUI가 멈추지 않고 데이터를 받을 수 있게 하였습니다.
recv에서는 연결되어있는동안 계속 recv()하며 빈데이터를 반환하면 소켓을 닫았다는 뜻으로 종료합니다.
길이가 정확히 16바이트면 그림파 동기화 패킷으로 간주하였습니다.
그 외의 데이터는 일반 문자열 메세지로 보고 디코딩 후 로그에 출력하였습니다.
FIXED/VST/MUX 패킷도 서버에서 처리한 뒤 클라이언트는 이렇게 문자열로 보일 수 있습니다.
cli_connect를 통해서 _recv_loop 루프를 빠져나오고 수신 스레드를 join()을 통해 정상 종료를 기다린 뒤 종료하였습니다.

# 9. 소켓 데이터 구조체 상태 표시

## SO_SNDBUF/SO_RCVBUF 조회

<img width="1093" height="739" alt="스크린샷 2025-12-10 오후 12 35 52" src="https://github.com/user-attachments/assets/a959f1bc-5998-411b-8a3c-e75f6787b6ba" />

클라이언트 연결된 소켓 버퍼를 조회하여 실제 연결된 TCP 소켓의 확장된 SEND/RECV 버퍼를 출력하였습니다.
임시 TCP 소켓 생성 후 버퍼 조회를 통해 OS 기본값을 확인할 수 있었고
결과를 GUI에 
출력하였습니다.

## 버퍼/소켓
```bash
    def _build_buf(self):
        top = ttk.Frame(self.pg_buf, padding=8);
        top.pack(fill="x")
        ttk.Button(top, text="클라 소켓 버퍼 조회", command=self.buf_client).pack(side="left", padx=4)
        ttk.Button(top, text="임시 소켓 버퍼 조회", command=self.buf_temp).pack(side="left", padx=4)
        self.out_buf = scrolledtext.ScrolledText(self.pg_buf, height=30)
        self.out_buf.pack(fill="both", expand=True)

    def log_buf(self, s):
        self._append(self.out_buf, s)

    # ---- 버퍼 스켈레톤 핸들러 ----
    def buf_client(self):
        if not self.client_connected or not self.client_socket:
            self.log_buf("[경고] 클라이언트가 연결되어 있지 않아 조회가 불가능합니다.")
            return

        self.log_buf("[버퍼] 클라이언트 소켓 버퍼 조회")

        try:
            snd_buf_size = self.client_socket.getsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF)
            self.log_buf(f"[송신 버퍼 (SO_SNDBUF)] 크기: {snd_buf_size} 바이트")

            rcv_buf_size = self.client_socket.getsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF)
            self.log_buf(f"[수신 버퍼 (SO_RCVBUF)] 크기: {rcv_buf_size} 바이트")

        except socket.error as e:
            self.log_buf(f"[오류] 소켓 버퍼 조회 실패: {e}")
        except Exception as e:
            self.log_buf(f"[예외] 예상치 못한 오류: {e}")

    def buf_temp(self):
        self.log_buf("[버퍼] 임시 소켓 생성 후 버퍼 조회")
        # TODO: socket() 후 옵션 조회

        # 임시 소켓 객체 생성
        temp_socket = None
        try:
            temp_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.log_buf("[정보] 임시 TCP 소켓 생성 완료.")

            # 송신 버퍼 (SO_SNDBUF) 크기 조회
            snd_buf_size = temp_socket.getsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF)
            self.log_buf(f"[송신 버퍼 (SO_SNDBUF)] 기본 크기: {snd_buf_size} 바이트")

            # 수신 버퍼 (SO_RCVBUF) 크기 조회
            rcv_buf_size = temp_socket.getsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF)
            self.log_buf(f"[수신 버퍼 (SO_RCVBUF)] 기본 크기: {rcv_buf_size} 바이트")

        except socket.error as e:
            self.log_buf(f"[오류] 소켓 작업 중 오류 발생: {e}")
        except Exception as e:
            self.log_buf(f"[예외] 예상치 못한 오류: {e}")

        finally:
            if temp_socket:
                temp_socket.close()
                self.log_buf("[정보] 임시 소켓 자원 해제 완료.")
```
_build_buf를 통해서 UI를 만들고 buf_client에서 getsockopt()를 통해 소켓 옵션 값을 읽어옵니다.
buf_temp에서 새로 TCP 소켓을 하나 만들어 서버에 연결하지 않고 연결 전 기본값이 무엇인지 확인할 수 있게 하였습니다. 
버퍼/소캣 탭에서는 getsockopt(SO_SNDBUF/SO_RCVBUF)를 사용하여 연결된 클라이언트 소켓과 임시 소켓의 버퍼 크기를 조회함으로써, 소켓 데이터 구조체 내부의 상태 변화를 확인할 수 있도록 하였습니다.

# 10. 네트워크 그림판

## 네트워크 그림판
<img width="1094" height="741" alt="스크린샷 2025-12-10 오후 12 46 28" src="https://github.com/user-attachments/assets/8944999c-adaa-429d-b859-82d2528b77ff" />

<img width="1094" height="741" alt="스크린샷 2025-12-10 오후 12 46 16" src="https://github.com/user-attachments/assets/0e413dea-453e-40e9-93a0-93528dc2f621" />

네트워크 그림판 탭에서 이렇게 그림을 그리면 클라이언트 상태 창에서 좌표들이 보이는 것들을 확인할 수 있었습니다.

## 네트워크 그림판
```bash
    # ---------------- 네트워크 그림판 ----------------
    def _build_draw(self):
        info = ttk.Frame(self.pg_draw, padding=8);
        info.pack(fill="x")
        ttk.Label(info, text="그림판 스켈레톤 — 드래그 시 선, (옵션) 네트워크 브로드캐스트").pack(side="left")
        self.canvas = tk.Canvas(self.pg_draw, bg="white", height=520)
        self.canvas.pack(fill="both", expand=True, padx=8, pady=8)
        self.canvas.bind("<ButtonPress-1>", self._draw_start)
        self.canvas.bind("<B1-Motion>", self._draw_move)
        self._last_xy = None

    def _draw_start(self, e):
        self._last_xy = (e.x, e.y)

    def _draw_move(self, e):
        if not self._last_xy: return
        x1, y1 = self._last_xy;
        x2, y2 = e.x, e.y
        self.canvas.create_line(x1, y1, x2, y2)
        # TODO: 네트워크로 동기화하려면 여기서 송신
        if self.client_connected and self.client_socket:
            try:
                packet = struct.pack('!IIII', x1, y1, x2, y2)

                self.client_socket.sendall(packet)
                self.log_cli(f"[Draw] 좌표 전송: ({x1},{y1}) -> ({x2},{y2})")  # 디버깅용

            except socket.error as err:
                self.log_cli(f"[오류] 드로잉 데이터 전송 실패: {err}")
                self.cli_close()
            except Exception as err:
                self.log_cli(f"[예외] 드로잉 전송 중 예상치 못한 오류: {err}")
        self._last_xy = (x2, y2)
```
_build_draw를 통해 하얀 캔버스를 하나 생성하고 마우스를 누르면 _draw_start(), 드래그하면 _drag_move()r가 호출됩니다.
이때의 좌표들을 클라이언트가 서버에 접속된 상태일때만 전송하여 struct를 이용한 전송형식을 사용하였습니다.
서버는 그림판 브로드캐스트 옵션이 켜져 있으면 다른 모든 클라이언트에게 동일 패킷을 전송합니다
```bash
ttk.Checkbutton(top, text="그림판 브로드캐스트", variable=self.var_broadcast).pack(side="left", padx=6)
```
```bash
    def _broadcast(self, data, exclude=None):
        with self.status_lock:
            targets = list(self.active_clients)
        for cs in targets:
            if cs is exclude:  # 보내온 클라 제외
                continue
            try:
                cs.sendall(data)
            except Exception as e:
                print("[ERROR] 브로드캐스트 실패:", e)
```
# 11, 12, 13, 14. 고정, 가변, 고전+가변 길이 전송 및 전송 후 종료

## 가변길이전송 클라이언트/서버
<img width="1094" height="745" alt="스크린샷 2025-12-10 오후 12 54 14" src="https://github.com/user-attachments/assets/4791c212-1742-4c9f-a84e-1d57a4aa92d9" />

<img width="1092" height="740" alt="스크린샷 2025-12-10 오후 12 54 35" src="https://github.com/user-attachments/assets/1f7e168a-db03-4018-b7ef-b8a87d67275b" />

가변길이전송이 이루어지는 것을 확인할 수 있습니다. Hello를 보냈고 Hello + "\n"까지 6B가 전송 및 구분된 것을 확인했습니다.

## 고정길이전송 클라이언트/서버
<img width="1094" height="745" alt="스크린샷 2025-12-10 오후 12 56 23" src="https://github.com/user-attachments/assets/8423e504-6e84-4d2a-a736-7c2f60f0da72" />

<img width="1093" height="743" alt="스크린샷 2025-12-10 오후 12 56 35" src="https://github.com/user-attachments/assets/de1fbde7-b8e8-470a-b9d9-7bd338985b19" />

고정길이전송이 이루어지는 것을 확인할 수 있습니다. Hello를 보냈고 Hello 5B 메세지에 패딩을 통해 32B가 전송된 것을 확인했습니다.

## 고정+가변길이전송 클라이언트/서버
<img width="1090" height="740" alt="스크린샷 2025-12-10 오후 12 57 26" src="https://github.com/user-attachments/assets/1cca4b0f-3f0d-4931-adbc-b808bae20bec" />

<img width="1093" height="743" alt="스크린샷 2025-12-10 오후 12 57 59" src="https://github.com/user-attachments/assets/1854a8fa-4498-4217-9fa9-b8a215c4d718" />

고정+가변길이전송이 이루어지는 것을 확인할 수 있습니다. Hello를 보냈고 Hello 5B 메세지와 앞에 헤더 4B 통해 보냈고 server에서 실제 5B를 인식한 것을 확인할 수 있습니다.

## 전송 후 종료 클라이언트/서버
<img width="1091" height="738" alt="스크린샷 2025-12-10 오후 1 01 59" src="https://github.com/user-attachments/assets/d96e046b-54dd-4ebc-a4fa-569c5b0baa12" />
<img width="1095" height="734" alt="스크린샷 2025-12-10 오후 1 02 17" src="https://github.com/user-attachments/assets/ff917211-792c-44f5-bf56-70eaff228fa3" />

고정+가변길이로 전송하고 전송 후 종료하도록 하였습니다. Hello 메세지가 전송되었고 연결 해제, 클라이언트 소켓 닫기, 수신 스레드 종료, 서버 연결 닫기, 클라이언트 소켓 정리 완료식으로 진행되었고 서버에서는 메세지를 수신한 뒤 클라이언트가 연결해제된 모습을 확인할 수 있습니다.

## 고정, 가변, 고정+가변길이전송
```bash
                if mode == "FIXED":
                FIXED_SIZE = 32

                # 버퍼 생성 및 데이터 채우기
                if data_length > FIXED_SIZE:
                    self.log_cli(f"[오류] FIXED 모드: 메시지 길이가 {FIXED_SIZE}바이트를 초과하여 전송 불가.")
                    return

                # 메시지를 담고 남은 공간은 널(0) 바이트로 채움
                padded_data = data_bytes.ljust(FIXED_SIZE, b'\0')

                self.client_socket.sendall(padded_data)
                self.log_cli(f"[전송] FIXED: {data_length}바이트 메시지 + 패딩 ({FIXED_SIZE}바이트 전송)")

            elif mode == "VAR":
                packet = data_bytes + b'\n'
                self.client_socket.sendall(packet)
                self.log_cli(f"[전송] VAR: 메시지 {len(data_bytes)}B + '\\n' (총 {len(packet)}B)")

            elif mode == "MIX":
                header = struct.pack('!I', len(data_bytes))
                packet = header + data_bytes
                self.client_socket.sendall(packet)
                self.log_cli(f"[전송] MIX: 헤더 4B + 메시지 {len(data_bytes)}B (총 {len(packet)}B)")
```
fixed는 항상 딱 32바이트를 보내도록 하였고 메세지가 짧으면 \0으로 패딩하였고 메세지가 길면 전송불가되도록 하였습니다. 
VAR은 메세지 뒤에 줄바꿈을 붙여서 보냅니다. 서버는 "\n"을 만나면 하나의 메세지 끝으로 간주하는 라인 기반 프로토콜을 사용합니다.
MIX 모드는 헤더(4바이트) + 실제 메시지를 보내도록 하였습니다.
```bash
            if after_close:
                self.cli_close()
```
after_close를 통해서 전송 후 cli_close()를 통해 클라이언트 접속을 닫아줍니다.

# 15, 16 멀티 스레드 동작 / 임계영역 및 이벤트
TCP 서버는 여러 클라이언트가 동시에 접속할 수 있어야합니다.
하나의 클라이언트가 접속했을 때마다 독립적인 스레드를 생성하여 처리하는 방식이 멀티스레드 서버입니다.
즉 메인 스레드: 서버 소켓 listen()
클라이언트 접속 시: 새로운 스레드 생성 -> 그 스레드가 클라이언트와 통신 유지합니다.

```bash
self.accept_thread = threading.Thread(target=self._accept_connections)
self.accept_thread.daemon = True
self.accept_thread.start()
```
accept loop thread

```bash
client_thread = threading.Thread(target=self._handle_client, args=(client_socket, addr))
client_thread.daemon = True
client_thread.start()
```
클라이언트마다 새로운 스레드 생성

```bash
with self.status_lock:
    self.active_clients.append(client_socket)
    self.client_counter += 1
```
active_clients / client_counter 갱신

임계영역/이벤트 기반 안전 종료
thireading.Lock()을 통하여 임계영역을 보호하여 여러 스레드가 동시에 동일한 데이터에 접근하면 데이터가 꼬일 수 있기 때문에 Lock이 필요합니다.

```bash
with self.status_lock:
    self.active_clients.append(client_socket)
    self.client_counter += 1
```
이를 통해 한 스레드가 실행 중일 때 다른 스레드가 이 영역에 들어오지 못하게 막는 기능입니다. 카운터 중복 방지합니다.

```bash
self.stop_event.clear()
```
서버 시작시 이벤트 초기화

```bash
while not self.stop_event.is_set():
    data = client_socket.recv(1024)
```
스레드 내부에서 종료 조건 체크

```bash
self.stop_event.set()
```
서버 정지 시 이벤트 설정

이를 통해 스레드가 즉시 루프를 빠져나오고 서버 종료시 모든 스레드가 안전하게 정리됩니다.

