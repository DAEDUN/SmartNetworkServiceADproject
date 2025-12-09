# 🛰 스마트 네트워크 / SFC 통합 GUI 도구  
**Course Project – Network Programming**  
**Author:** 홍길동 (2023123456)

---

## 📌 프로젝트 개요
이 프로젝트는 네트워크 실습에서 사용되는 기능들을 하나의 GUI 프로그램(Tkinter)에서 통합적으로 데모할 수 있도록 구성한 시스템입니다.  
총 **16개의 요구사항**을 모두 충족하도록 설계되었으며, TCP 서버/클라이언트, DNS/바이트 변환, 포트 검사, 소켓 버퍼 조회, 네트워크 그림판(브로드캐스트)까지 포함합니다.

프로그램은 **Windows / macOS / Linux 전체 지원**을 목표로 합니다.

---

# ✔️ 요구사항 체크리스트 (16개 기능)

## 🔧 네트워크 진단 기능
- [x] IP 구성 확인 (ipconfig / ifconfig 자동 분기)
- [x] DNS 조회
- [x] 역방향 DNS 조회
- [x] inet_pton / inet_ntop 변환
- [x] hton / ntoh (바이트 오더 변환)
- [x] 포트 오픈 여부 검사
- [x] netstat 필터 (Windows: findstr / Unix: grep)

## 🔌 TCP 서버 / 클라이언트 기능
- [x] TCP 서버 시작 / 정지
- [x] 클라이언트 접속/해제 표시
- [x] 전송 모드: VAR (개행 구분 가변 전송)
- [x] 전송 모드: FIXED (정확히 N바이트)
- [x] 전송 모드: MIX (4-byte 길이 prefix + payload)
- [x] “전송 후 종료” 옵션 (send → close)
- [x] 클라이언트별 스레드(Thread per client)
- [x] 공유 카운터 + Lock (임계영역 보호)
- [x] Event 기반 서버 안전 종료

## 🖼 네트워크 그림판
- [x] 마우스 드래그로 그림 그리기
- [x] 서버가 그림 좌표를 브로드캐스트

## 🧰 버퍼 / 소켓 정보
- [x] SO_SNDBUF / SO_RCVBUF 조회 기능

---

# 📊 요구사항 매핑 표 (제출용)

| 번호 | 요구사항 | 구현 위치 | 상태 |
|------|-----------|-----------|-------|
| 1 | IP 구성 확인 | 네트워크 진단 탭 | ✔️ |
| 2 | 바이트 정렬 hton/ntoh | 네트워크 진단 | ✔️ |
| 3 | IP 변환 pton/ntop | 네트워크 진단 | ✔️ |
| 4 | DNS/역방향 조회 | 네트워크 진단 | ✔️ |
| 5 | 포트 검사 | 네트워크 진단 | ✔️ |
| 6 | netstat 필터 | 네트워크 진단 | ✔️ |
| 7 | TCP 서버 상태 표시 | TCP 서버 탭 | ✔️ |
| 8 | TCP 클라이언트 | TCP 클라이언트 탭 | ✔️ |
| 9 | 소켓 버퍼 조회 | 버퍼/소켓 탭 | ✔️ |
| 10 | 네트워크 그림판 | 그림판 탭 | ✔️ |
| 11 | FIXED 전송 | 클라이언트 | ✔️ |
| 12 | VAR 전송 | 클라이언트 | ✔️ |
| 13 | MIX 전송 | 클라이언트 | ✔️ |
| 14 | 전송 후 종료 | 클라이언트 옵션 | ✔️ |
| 15 | Lock(임계영역) | 서버 스레드 | ✔️ |
| 16 | Event(안전 종료) | 서버 종료 루틴 | ✔️ |

---

# ▶️ 실행 방법

## 📍 macOS (python.org 버전 사용 권장)
```bash
/Library/Frameworks/Python.framework/Versions/3.11/bin/python3 smart_net_suite.py
