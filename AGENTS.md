# Linux 커널 작업 원칙

## 경로 정의

- `linux` = `/home/leedaeeun/Documents/github/linux` (이 저장소)
- `libfuse` = `/home/leedaeeun/Documents/github/libfuse`
- `fuse_kbuild_tools` = `/home/leedaeeun/Documents/github/fuse_kbuild_tools`
- `fuse_exp` = `/home/leedaeeun/Documents/github/fuse_exp`
- `ExtFUSE_Code` = `/home/leedaeeun/Documents/github/ExtFUSE_Code`
- `research_exp` = `/home/leedaeeun/Documents/github/research_exp`

이하 본문의 `<이름>/<하위경로>` 표기는 모두 위 절대경로 기준이며, 현재 shell의 작업
디렉터리와 무관하게 유효하다.

## 기본 원칙

- 상위 지시를 제외하면 사용자의 현재 명시적 지시가 우선하며, 하위 경로에서는
  가장 가까운 `AGENTS.override.md` 또는 `AGENTS.md`를 따른다.
- 작업 전 repository root, `git status --short --branch`, HEAD와 대상 경로의
  tracked, staged, untracked 상태를 확인한다. 큰 kernel tree의 전체 diff보다 먼저
  diff stat을 보고 요청 관련 path의 diff를 읽는다.
- 기존 tracked, staged, untracked 변경은 사용자 작업이다. 요청과 관련된
  파일만 수정하고 기존 작업을 삭제하거나 덮어쓰지 않는다.
- 분석·설명·review는 읽기 전용이다. 구현 요청은 관련 source 수정과 local
  build 검증만 허용하며 Git 쓰기나 시스템 변경 권한까지 포함하지 않는다.
- `libfuse`, `ExtFUSE_Code`, `fuse_exp`, `fuse_kbuild_tools`, `research_exp` 등
  sibling tree는 별도 범위다. 요청 없이 수정하거나 산출물을 남기지 않는다.

## Sibling 저장소

- `libfuse` — 대응 userspace FUSE 라이브러리. modern 조합에서는 branch
  `fuse-3.18.2-ExtFUSE`가 이 저장소의 `ExtFUSE-v6.19.14`와 짝을 이룬다.
- `fuse_kbuild_tools` — 이 저장소의 유일한 커널 config/build/install/배포
  진입점. 이 tree에서 직접 `make`하지 않고 항상 이 저장소를 거친다.
- `fuse_exp` — benchmark workload, 실험 정책과 결과. 이 저장소가 build한
  커널을 대상으로 benchmark를 수행한다.
- `ExtFUSE_Code` — 원본 USENIX ATC'19 ExtFUSE 참조 구현(read-only archive).
  semantic port와 modern hardening 변경을 비교하는 기준점.
- `research_exp` — cross-repo 격리 build/copy-out 공간. 이 저장소에서 직접
  사용하지 않으며, 다른 저장소가 이 tree를 참조·복사할 때 쓰인다.

## ExtFUSE 범위와 호환성

- 이 저장소는 kernel FUSE driver다. 대응 userspace는 `libfuse`, 실험 정책과
  결과는 `fuse_exp`, 커널 설정·빌드·배포 도구는 `fuse_kbuild_tools`가 맡는다.
- 예상 modern 조합은 Linux `ExtFUSE-v6.19.14`와 libfuse
  `fuse-3.18.2-ExtFUSE`다. 연동 전 양쪽의 branch, commit과 변경 상태를 확인하고,
  protocol, UAPI, capability, INIT, ABI, ExtFUSE와 io_uring을 함께 검토한다.
- 코드와 설명은 `ExtFUSE_Code`의 semantic port, modern 호환·hardening, 원본에
  없던 passthrough coherence·notification·io_uring 확장을 구분한다.
- `-ENOSYS`는 ExtFUSE의 정상 daemon fallback이다. 다른 errno completion을
  fallback이나 cache hit로 해석하지 않는다.
- source 존재, compile, BPF 등록·load, map population과 runtime hit는 각각
  별도 증거다. 과거 결과는 manifest와 실제 BPF object hash를 확인한다.

## Git, source와 `.config`

- Git은 기본적으로 조회에만 사용한다. `status`, `diff`, `log`, `show`, `grep`,
  `blame`, `ls-files`, `rev-parse` 등은 허용한다.
- working tree, history, refs, remote 또는 `git config`를 바꾸는 명령은 별도
  허가가 필요하다. 코드 수정 허가를 Git 상태 변경 허가로 확대하지 않는다.
- remote URL과 repository-local config에는 credential userinfo가 있을 수 있으므로
  `git remote -v`, `git config --list`, `linux/.git/config` 또는 raw URL을 출력하지
  않는다. 필요하면 credential/userinfo를 제거한 host/path만 보고한다.
- 요청 범위의 최소 diff를 만들고 관련 없는 cleanup, rename, reformat 또는
  generated artifact를 섞지 않는다. C는 kernel coding style을 따르며,
  커밋 전 `linux/scripts/checkpatch.pl --no-tree -f <file>`로 스타일을 점검한다
  (diff 대상이면 `--no-tree -g <rev>`로 커밋 단위 점검도 가능).
- 커널 `.config`는 Git에서 무시되는 build configuration이다. 별도 허가 없이
  재생성할 수 있는 대상은 선택한 profile의 out-of-tree `BUILDDIR/.config`뿐이며,
  이 재생성은 Linux source/Git 변경으로 취급하지 않는다.
- Linux source tree의 `.config`, 사용자가 지정한 seed config와 다른 build
  directory의 config는 사용자 작업이다. 읽기만 하고 생성·변경·삭제에는 별도
  허가가 필요하다.
- profile 정의·수정과 profile에서 `.config`를 만드는 규칙은 `fuse_kbuild_tools`
  저장소의 책임이며 `fuse_kbuild_tools/AGENTS.md`를 따른다.
- `.config` 변경 허용은 tracked source 변경, 기존 build 결과 삭제, kernel 설치
  또는 다른 시스템 변경 권한을 뜻하지 않는다.

## 명령과 시스템 안전

- 요청 범위의 source patch와 빌드 검증에 필요한 `BUILDDIR/.config` 갱신을
  제외하고, 기존 file·directory를 삭제·비우기·덮어쓰기·이동하는 shell 동작은
  별도 허가가 필요하다. `rm`, `find -delete`, `truncate`, 기존 대상을 덮는
  `cp`·`mv`와 delete 옵션이 있는 동기화 명령을 자동 cleanup 수단으로 사용하지
  않는다.
- 삭제·덮어쓰기 전에는 physical target과 영향 범위를 확인한다. `/`, `~`, repository
  root, 비어 있거나 검증되지 않은 변수·glob을 대상으로 삼지 않고, persistent build
  cache를 clean 검증 목적으로 지우지 않는다. 필요하면 허가받은 새 task-specific
  build root를 사용한다.
- `sudo`, `doas`, `su`, root shell, package 설치·갱신·삭제와 `systemctl` 등
  service·system 상태를 바꾸는 명령은 각각 명시적 허가가 필요하다. 코드 수정이나
  local build 요청은 비밀번호 prompt가 없더라도 privilege escalation 또는 system
  변경 허가가 아니다.

## 빌드와 검증

- 커널 빌드가 필요하면 Linux source tree에서 직접 `make`하지 말고 `fuse_kbuild_tools`로
  이동해 `fuse_kbuild_tools/AGENTS.md`를 확인한 뒤 빌드한다.
- 현재 `ExtFUSE-v6.19.14` checkout에는 범위가 다른 두 profile이 있다.
  `6.19.14-ExtFUSE`는 metadata fast path와 daemon-routed I/O 기준선
  (`CONFIG_FUSE_PASSTHROUGH=n`)이고, `6.19.14-ExtFUSE-AllOpt`는 native
  passthrough/coherence까지 포함한다. 둘 다 ExtFUSE와 FUSE-over-io_uring을
  포함한다.
- metadata-only·daemon-routed I/O 변경은 `6.19.14-ExtFUSE`, passthrough,
  backing-file 또는 coherence 변경은 `6.19.14-ExtFUSE-AllOpt`를 선택한다.
  공통 FUSE/UAPI/INIT/config guard를 바꾸거나 두 구성을 모두 지원한다고 결론 내릴
  때는 두 profile을 각각 build한다. profile 전용 변경이면 해당 profile만 검증한다.
- `linux/kernel/configs/extfuse-allopt.config`는 profile의 source marker일 뿐 build
  입력 자체가 아니다. 이 fragment를 바꾸면 tool의 AllOpt `profile_kconfig()`와
  동기화해 실제 생성 `.config`를 검증하며, marker 존재만으로 내용이나 commit
  identity를 증명하지 않는다.
- 실행 전 Linux branch·HEAD와 선택한 tool profile의 source 계약이 일치하는지
  확인한다. branch나 kernel target이 다르면 위 이름을 재사용하지 말고 도구
  저장소의 현재 profile 정의를 다시 확인한다. 일치하면 다음 wrapper를 기본
  진입점으로 사용한다. wrapper는 tool checkout에 실제로 존재하고 검토된 경우에만
  사용한다.

  ```bash
  cd fuse_kbuild_tools
  SELECTED_PROFILE=6.19.14-ExtFUSE  # 또는 6.19.14-ExtFUSE-AllOpt
  ./build_only.sh -p "${SELECTED_PROFILE}"
  ```

- `fuse_kbuild_tools/build_only.sh`가 없으면 Linux source에서 직접 `make`하지 말고,
  같은 `SELECTED_PROFILE`로 도구의 세 단계를 명시적으로 실행한다.

  ```bash
  SUDO_AUTO_PASSWORD=no ./doctor.sh -p "${SELECTED_PROFILE}"
  SUDO_AUTO_PASSWORD=no ./1_prepare_config.sh -p "${SELECTED_PROFILE}"
  SUDO_AUTO_PASSWORD=no ./2_build_install_kernel.sh \
    -p "${SELECTED_PROFILE}" --incremental --build-only
  ```

  (위 세 스크립트는 `fuse_kbuild_tools` 안에서 실행한다.)

- `build_only.sh`는 local 환경을 점검하고 `.config`를 seed에서 매번 다시 생성해
  최신 profile Kconfig를 적용한 뒤 incremental build-only를 수행한다.
- wrapper는 기존 object와 compile cache를 보존한다. `--fresh`, `--full`, 기존
  build directory 삭제와 source fetch는 기본 검증에 포함하지 않는다.
- build path, 산출물, expected kernel release, cache와 0·1·2번 스크립트의 세부
  규칙은 `fuse_kbuild_tools/AGENTS.md`를 단일 기준으로 삼는다. 성공 후 그 문서가
  요구하는 결과를 확인하고 실제 build path, profile과 Linux/tool HEAD를 보고한다.
- build-only 결과는 compile/config 검증용이다. 설치가 명시적으로 요청돼도
  도구 저장소의 권한 경계를 다시 확인한다. 산출물을 수동 복사하지 않으며
  kernel/module 설치, `/boot`, initramfs, GRUB 변경과 reboot는 각각 별도 허가가
  필요하다.
- kernel/module 설치·교체, bootloader 변경, reboot, mount, sysctl/module
  parameter 변경, tracing과 benchmark는 각각 명시적인 허가가 필요하다.
- 결론은 source/static, config, build/ABI, runtime activation, functional,
  request-count와 performance evidence를 구분한다. 실제 수행한 단계만 성공으로
  보고한다.
- ExtFUSE runtime에는 booted kernel/config, 대응 libfuse/daemon, INIT 협상,
  BPF object와 handler/map/request trace 증거가 필요하다.
- FUSE-over-io_uring runtime에는 negotiation, queue registration,
  `ring->ready`, `fuse-ring-*` worker와 `COMMIT_AND_FETCH` 증거가 필요하다.
- benchmark는 `fuse_exp`의 지시와 workload를 따르며 같은 run의 paired result를
  비교한다. build나 다른 환경의 절대값을 runtime/performance 증거로 대신하지
  않는다.

## 완료 보고

- 자동으로 stage, commit 또는 push하지 않는다. 필요하면 관련 파일만 지정한
  `git add`, 영어 commit subject, 한국어 설명과 push 명령을 제안한다.
- 변경 파일, 주요 변경, 수행한 검증과 실행하지 않은 단계를 한국어로 간단히
  보고한다.
