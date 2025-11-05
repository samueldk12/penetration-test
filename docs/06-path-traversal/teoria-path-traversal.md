# Teoria Fundamental de Path Traversal

**Criticidade**: 🔴 Crítica (CVSS 7.5-9.5)
**Dificuldade**: 🟡 Intermediária
**Bounty Médio**: $2,000 - $15,000 USD

---

## 📚 Índice

1. [Fundamentos de Filesystem](#fundamentos-de-filesystem)
2. [Path Resolution e Normalização](#path-resolution-e-normalização)
3. [Kernel VFS (Virtual File System)](#kernel-vfs-virtual-file-system)
4. [Por Que Path Traversal Existe](#por-que-path-traversal-existe)
5. [Symlinks e Hard Links](#symlinks-e-hard-links)
6. [Teoria de Canonicalização](#teoria-de-canonicalização)

---

## 🔬 Fundamentos de Filesystem

### O Que É Path Traversal em Essência?

**Path Traversal** é uma violação de **controle de acesso a arquivos** que ocorre quando:

1. **Aplicação permite usuário especificar caminho de arquivo**
2. **Path não é validado ou normalizado**
3. **Usuário pode navegar fora do diretório pretendido**

### Estrutura de Diretórios Unix

**Hierarchical File System:**

```
/                           (root)
├── bin/                    (executáveis do sistema)
├── etc/                    (configurações)
│   ├── passwd              (usuários)
│   ├── shadow              (senhas hash)
│   └── apache2/
│       └── apache2.conf
├── home/                   (diretórios de usuários)
│   ├── alice/
│   └── bob/
├── var/
│   ├── www/
│   │   └── html/           (web root)
│   │       ├── index.html
│   │       └── uploads/
│   └── log/
│       └── apache2/
│           └── access.log
└── tmp/                    (arquivos temporários)
```

**Conceitos de Path:**

```
Absolute Path: /home/alice/document.txt
  - Começa com /
  - Path completo desde root

Relative Path: uploads/file.txt
  - Não começa com /
  - Relativo ao diretório atual (CWD)

Current Directory: .
  ./file.txt = file.txt

Parent Directory: ..
  ../file.txt = um nível acima
```

### Path Traversal Attack Model

**Cenário Vulnerable:**

```python
# Application code
@app.route('/download')
def download_file():
    filename = request.args.get('file')
    # Intended: arquivos em /var/www/html/uploads/
    filepath = f"/var/www/html/uploads/{filename}"
    return send_file(filepath)

# Normal usage:
GET /download?file=document.pdf
→ /var/www/html/uploads/document.pdf ✓

# Attack:
GET /download?file=../../../../etc/passwd
→ /var/www/html/uploads/../../../../etc/passwd
→ /etc/passwd ← FORA do diretório pretendido!
```

**Matemática do Traversal:**

```
Base: /var/www/html/uploads/  (4 níveis de profundidade)
Traversal: ../../../../        (4 × ".." sobe 4 níveis)

Resolução:
  /var/www/html/uploads/../../../../etc/passwd
= /var/www/html/uploads/../../../ ../etc/passwd
= /var/www/html/../../../ ../etc/passwd
= /var/www/../../../ ../etc/passwd
= /var/../../ ../etc/passwd
= /../ ../etc/passwd
= / ../etc/passwd
= /etc/passwd ✓

Regra: ../ cancela um nível
```

---

## 🛤️ Path Resolution e Normalização

### Kernel Path Resolution Process

**Quando programa faz open("/var/www/../etc/passwd"):**

```
1. Parse path em componentes:
   ["", "var", "www", "..", "etc", "passwd"]
   ↑ Leading "/" cria componente vazio

2. Walk the path (kernel VFS layer):

   Current: / (root inode)

   Component "var":
     Lookup "var" in / → inode 1234
     Current: /var

   Component "www":
     Lookup "www" in /var → inode 5678
     Current: /var/www

   Component "..":
     ↑ SPECIAL: vai para parent
     Current: /var

   Component "etc":
     Lookup "etc" in /var → inode 2468
     Current: /var/etc
     ✗ /var/etc não existe → ENOENT error

   (Se /etc existisse no nível correto:)
   Current: /etc

   Component "passwd":
     Lookup "passwd" in /etc → inode 9876
     Current: /etc/passwd

3. Return inode 9876
```

**Estrutura de Inode:**

```c
// fs/inode.c (Linux kernel)
struct inode {
    umode_t         i_mode;     // File type and permissions
    uid_t           i_uid;      // Owner user ID
    gid_t           i_gid;      // Owner group ID
    loff_t          i_size;     // File size in bytes
    struct timespec i_atime;    // Access time
    struct timespec i_mtime;    // Modification time
    struct timespec i_ctime;    // Status change time
    unsigned long   i_ino;      // Inode number
    struct super_block *i_sb;   // Filesystem superblock
    struct inode_operations *i_op;  // Inode operations
    struct file_operations *i_fop;  // File operations
    void            *i_private; // Filesystem-specific data
};
```

### Directory Entry (dentry) Cache

**Kernel mantém cache de paths:**

```c
// include/linux/dcache.h
struct dentry {
    struct dentry *d_parent;    // Parent dentry
    struct qstr d_name;         // Component name
    struct inode *d_inode;      // Associated inode
    struct list_head d_subdirs; // Child dentries
    struct hlist_node d_hash;   // Hash table linkage
    // ...
};
```

**Exemplo de dentry tree:**

```
/var/www/html/uploads/file.txt

Dentry tree:
    / (root)
    └── var/
        └── www/
            └── html/
                └── uploads/
                    └── file.txt

Cada dentry aponta para:
  - Parent dentry
  - Child dentries (siblings)
  - Associated inode
```

**Path Traversal explora:**

```
Component ".." → Kernel segue d_parent pointer
  /var/www/html/..
  ↓
  d_parent de /var/www/html → /var/www

Repetir ".." múltiplas vezes:
  ../../../../
  ↓
  Chega em / (root) → d_parent de / é NULL ou aponta para si mesmo
```

---

## 🗄️ Kernel VFS (Virtual File System)

### VFS Abstraction Layer

**VFS permite acesso uniforme a diferentes filesystems:**

```
Application Layer
    ↓ system calls (open, read, write)
VFS Layer (abstração)
    ↓
Filesystem Implementations
    ├── ext4
    ├── xfs
    ├── btrfs
    ├── nfs (network)
    └── tmpfs (memory)
    ↓
Block Device Layer
    ↓
Physical Storage
```

**VFS Operations:**

```c
// include/linux/fs.h
struct inode_operations {
    int (*create) (struct inode *,struct dentry *,umode_t, bool);
    struct dentry * (*lookup) (struct inode *,struct dentry *, unsigned int);
    int (*link) (struct dentry *,struct inode *,struct dentry *);
    int (*unlink) (struct inode *,struct dentry *);
    int (*symlink) (struct inode *,struct dentry *,const char *);
    int (*mkdir) (struct inode *,struct dentry *,umode_t);
    int (*rmdir) (struct inode *,struct dentry *);
    // ...
};

struct file_operations {
    loff_t (*llseek) (struct file *, loff_t, int);
    ssize_t (*read) (struct file *, char __user *, size_t, loff_t *);
    ssize_t (*write) (struct file *, const char __user *, size_t, loff_t *);
    int (*open) (struct inode *, struct file *);
    int (*release) (struct inode *, struct file *);
    // ...
};
```

### open() System Call Flow

```
User space:
  fd = open("/etc/passwd", O_RDONLY)

Kernel space:

1. sys_open() (syscall entry)
   ↓
2. do_sys_open()
   ↓
3. getname() - copy path from user space
   ↓
4. get_unused_fd() - allocate fd number
   ↓
5. do_filp_open()
   ↓
6. path_openat()
   ↓
7. link_path_walk() - RESOLVE PATH
   ↓
   For each component:
     - lookup_fast() - check dentry cache
     - If not cached:
       - lookup_slow() → inode->lookup()
       - Add to dentry cache
   ↓
8. Check permissions (permission())
   ↓
9. vfs_open()
   ↓
10. inode->open() - filesystem-specific open
   ↓
11. Return fd to user space
```

**Path Traversal não é bloqueado porque:**

```
Kernel perspective:
  "/var/www/html/../../../../etc/passwd"

É path VÁLIDO que resolve para: /etc/passwd

Kernel não sabe:
  - Qual era o "diretório pretendido" da aplicação
  - Que ".." representa "travessia não autorizada"

Kernel apenas:
  - Resolve path normalmente
  - Verifica permissões de PROCESSO (UID, GID)
  - Se processo tem read permission em /etc/passwd → PERMITE
```

---

## 🚫 Por Que Path Traversal Existe

### 1. Ausência de Jail/Chroot

**chroot() System Call:**

```c
// Change root directory
int chroot(const char *path);

// After chroot("/var/www/html"):
//   / is now /var/www/html
//   Cannot access real /etc/passwd
```

**Como funciona:**

```
Before chroot:
  Process sees:
    / → real filesystem root

After chroot("/var/www/html"):
  Process sees:
    / → /var/www/html (on real filesystem)
    /uploads/ → /var/www/html/uploads/

  Path traversal:
    ../../etc/passwd
    Resolves to: /var/www/etc/passwd (NOT /etc/passwd!)
    ✓ Confined!
```

**Problema: Não é usado em aplicações web típicas**

```
Razões:
  - chroot() requer root privileges
  - Complexo de configurar (need /lib, /bin, etc. inside chroot)
  - Performance overhead
  - Não é completamente seguro (escape techniques exist)
```

### 2. Confusão entre Path Relativo e Absoluto

**Aplicação assume path relativo:**

```python
# Vulnerable assumption
base_dir = "/var/www/html/uploads"
user_file = request.args.get('file')

# Concatenação ingênua
full_path = base_dir + "/" + user_file
# Assumption: user_file is relative path

# Attack:
user_file = "/etc/passwd"  # Absolute path!

# Result:
full_path = "/var/www/html/uploads" + "/" + "/etc/passwd"
          = "/var/www/html/uploads//etc/passwd"
          ↑ Em Unix, // = /
          = "/etc/passwd"
```

**Por que // = / ?**

```
Unix path resolution:
  - Leading / indicates absolute path
  - Multiple / are collapsed to single /

  //etc/passwd = /etc/passwd
  ///etc/passwd = /etc/passwd
  /var//www///html = /var/www/html

Anywhere in path:
  /var/www/html//etc/passwd
  ↓
  /var/www/html/etc/passwd
```

### 3. URL Encoding e Bypass

**Double Encoding:**

```
URL encoding:
  / → %2F
  . → %2E

Path traversal:
  ../../ → ..%2F..%2F

Double encoding:
  %2F → %252F

Attack:
  user_input = "..%252F..%252F..%252Fetc%252Fpasswd"

Application decodes once:
  "..%2F..%2F..%2Fetc%2Fpasswd"

Application validation:
  Check for "../" → NOT FOUND ✓ (thinks it's safe)

Server/OS decodes again:
  "../../../../etc/passwd" ← Attack succeeds!
```

---

## 🔗 Symlinks e Hard Links

### Symbolic Links (Symlinks)

**O que são:**

```
Symlink = arquivo especial que aponta para outro arquivo/diretório

Tipo: i_mode = S_IFLNK
Conteúdo: path do target

Exemplo:
  /var/www/html/files/secret → /etc/passwd
```

**Criação:**

```bash
ln -s /etc/passwd /var/www/html/files/secret
```

**Estrutura no disco:**

```
inode 1234 (symlink /var/www/html/files/secret):
  i_mode = S_IFLNK | 0777
  i_size = 11 ("/etc/passwd" tem 11 bytes)
  data blocks: "/etc/passwd"

inode 5678 (file /etc/passwd):
  i_mode = S_IFREG | 0644
  i_size = 2048
  data blocks: [user data]
```

**Path Traversal via Symlink:**

```
Scenario:
  1. Atacante cria symlink no diretório de upload
     ln -s /etc/passwd /var/www/html/uploads/public_file.txt

  2. Aplicação serve arquivos de uploads/
     GET /download?file=public_file.txt

  3. Kernel segue symlink:
     open("/var/www/html/uploads/public_file.txt")
     → inode diz: "I'm a symlink to /etc/passwd"
     → Kernel abre /etc/passwd
     → ✗ /etc/passwd vazado!
```

**readlink() System Call:**

```c
// Read symlink target
ssize_t readlink(const char *pathname, char *buf, size_t bufsiz);

// Example:
char target[PATH_MAX];
ssize_t len = readlink("/var/www/html/files/secret", target, sizeof(target));
// target = "/etc/passwd"
```

### Hard Links

**O que são:**

```
Hard link = múltiplos nomes (dentries) apontando para MESMO inode

Diferença de symlink:
  Symlink: novo inode (tipo S_IFLNK) → aponta para path
  Hard link: mesmo inode, múltiplos nomes
```

**Exemplo:**

```bash
# Cria hard link
ln /etc/passwd /var/www/html/uploads/data.txt

# Agora:
/etc/passwd                      → inode 1234
/var/www/html/uploads/data.txt   → inode 1234 (MESMO inode!)

# inode 1234:
  i_nlink = 2  (link count)
  i_mode = S_IFREG | 0644
```

**Path Traversal via Hard Link:**

```
Scenario:
  1. Atacante cria hard link
     ln /etc/shadow /var/www/html/uploads/public.txt
     ↑ Só funciona se attacker tem permissão!

  2. Aplicação serve arquivo
     GET /download?file=public.txt
     → Retorna conteúdo de /etc/shadow!
```

**Limitações de Hard Links:**

```
Não podem:
  - Atravessar filesystems (cross-device)
  - Linkar diretórios (exceto por root, e perigoso!)

Podem:
  - Ser usados para bypass de quotas
  - Persistir após delete do original (i_nlink > 0)
```

---

## 📏 Teoria de Canonicalização

### O Que É Canonicalização?

**Canonicalização** = Converter path para sua forma **canônica** (normalizada, absoluta, sem ambiguidades)

**Paths não-canônicos:**

```
/var/www/../var/www/html
/var/www/./html
/var/www//html
/var/www/html/
/var/www/html/.
```

**Path canônico:**

```
/var/www/html
```

### Algoritmo de Canonicalização

**Regras:**

```
1. Resolver "." (current directory)
   /var/./www → /var/www

2. Resolver ".." (parent directory)
   /var/www/../lib → /var/lib

3. Remover "/" duplicados
   /var//www///html → /var/www/html

4. Remover trailing "/"
   /var/www/ → /var/www

5. Converter para absolute path
   var/www → /current/dir/var/www

6. Resolver symlinks
   /var/www/link → /var/www/target
```

**Implementação:**

```python
import os

def canonicalize(path):
    """Canonicalize path."""
    # 1. Convert to absolute path
    abs_path = os.path.abspath(path)

    # 2. Resolve symlinks
    canonical = os.path.realpath(abs_path)

    # 3. Normalize (remove .., ., //)
    normalized = os.path.normpath(canonical)

    return normalized

# Examples:
canonicalize("../../../etc/passwd")
# → "/etc/passwd"

canonicalize("/var/www/./html/../html")
# → "/var/www/html"
```

### realpath() - Kernel Function

**C Library Function:**

```c
#include <limits.h>
#include <stdlib.h>

char *realpath(const char *path, char *resolved_path);
```

**O que faz:**

```
1. Resolve todos symlinks
2. Resolve ./ e ../
3. Retorna absolute path
4. Verifica se path existe

Example:
  Input: /var/www/html/../uploads/./file.txt
  Output: /var/www/uploads/file.txt

  Input: /var/www/symlink (→ /etc)
  Output: /etc
```

**Uso para Prevenir Path Traversal:**

```c
char *safe_path(const char *base, const char *user_path) {
    char full_path[PATH_MAX];
    char canonical[PATH_MAX];

    // 1. Concatenar
    snprintf(full_path, sizeof(full_path), "%s/%s", base, user_path);

    // 2. Canonicalize
    if (realpath(full_path, canonical) == NULL) {
        return NULL;  // Path doesn't exist or error
    }

    // 3. Check if canonical path starts with base
    if (strncmp(canonical, base, strlen(base)) != 0) {
        // Traversal detected!
        return NULL;
    }

    return strdup(canonical);
}

// Usage:
char *path = safe_path("/var/www/html", "../../../../etc/passwd");
// path = NULL (blocked!)

char *path = safe_path("/var/www/html", "uploads/file.txt");
// path = "/var/www/html/uploads/file.txt" (allowed)
```

---

## 🔐 Análise de Segurança Formal

### Definição de Segurança

**Sistema é seguro se:**

```
∀ path ∈ User_Input:
  Resolved(base_dir, path) ∈ Subtree(base_dir)

Onde:
  Resolved(base, path) = canonicalize(base + "/" + path)
  Subtree(base) = {f | f inicia com base}

Exemplo:
  base_dir = "/var/www/html"

  path1 = "uploads/file.txt"
  Resolved = "/var/www/html/uploads/file.txt"
  ∈ Subtree("/var/www/html") ✓

  path2 = "../../../../etc/passwd"
  Resolved = "/etc/passwd"
  ∉ Subtree("/var/www/html") ✗ VIOLAÇÃO!
```

### TOCTOU (Time-Of-Check to Time-Of-Use)

**Race Condition em Path Validation:**

```python
# Thread 1 (application):
def serve_file(filename):
    path = "/var/www/html/uploads/" + filename

    # TIME OF CHECK
    canonical = os.path.realpath(path)
    if not canonical.startswith("/var/www/html/"):
        return "Forbidden"

    # ← WINDOW OF VULNERABILITY

    # TIME OF USE
    with open(canonical, 'r') as f:
        return f.read()

# Thread 2 (attacker):
# During WINDOW:
os.remove("/var/www/html/uploads/file.txt")
os.symlink("/etc/passwd", "/var/www/html/uploads/file.txt")

# Result: check sees legitimate file
#         use reads /etc/passwd
```

**Solução: Open + fstat**

```c
// Atomic check-and-use
int safe_open(const char *base, const char *user_path) {
    char full_path[PATH_MAX];
    snprintf(full_path, sizeof(full_path), "%s/%s", base, user_path);

    // Open file (gets inode)
    int fd = open(full_path, O_RDONLY);
    if (fd < 0) return -1;

    // Get file info via fd (not path!)
    struct stat st;
    if (fstat(fd, &st) < 0) {
        close(fd);
        return -1;
    }

    // Check if file is as expected
    if (S_ISLNK(st.st_mode)) {
        // Symlink → reject
        close(fd);
        return -1;
    }

    // Now safe to use fd
    return fd;
}
```

---

## 📊 Complexidade de Defesa

### Problema da Validação Completa

**Por que é difícil:**

```
Considerações:
1. Múltiplos encodings (UTF-8, UTF-16, percent encoding)
2. Múltiplos separadores (/, \, mixed)
3. Normalização de Unicode (NFC, NFD, NFKC, NFKD)
4. Case sensitivity (Windows vs Unix)
5. Symlinks podem mudar
6. Race conditions (TOCTOU)
7. Filesystem-specific quirks

Combinações = Exponencial!
```

**Defense in Depth:**

```
Layer 1: Input Validation
  - Whitelist caracteres permitidos
  - Reject "." e ".."
  - Reject absolute paths

Layer 2: Path Normalization
  - realpath() ou equivalente
  - Remove ./, ../, //

Layer 3: Prefix Check
  - Verificar canonical path starts with base

Layer 4: Filesystem Isolation
  - chroot, containers, jails

Layer 5: Least Privilege
  - Process roda com UID limitado
  - Não pode acessar /etc/ mesmo se traversal funcionar
```

---

**Última atualização**: 2024
**Versão**: 1.0 - Documento Teórico Fundamental
