# bypassKeyAttestation 

## Key Attestation 密钥认证

官方文档介绍： https://source.android.com/docs/security/features/keystore/attestation，

个人理解，硬件提供加密功能，同时该硬件模块也会反映设备的软硬件的安全环境。

不想自己实现一套代码的，可以直接用开源的:

 https://github.com/vvb2060/KeyAttestation

功能入口 https://github.com/vvb2060/KeyAttestation/blob/master/app/src/main/java/io/github/vvb2060/keyattestation/home/HomeViewModel.kt  doAttestation方法：
### 获取证书链

![image-20231206194441375](assets/image-20231206194441375.png)

### 解析证书链

![image-20231206194902623](assets/image-20231206194902623.png)

### 对证书进行校验

![image-20231206204618107](assets/image-20231206204618107.png)

### 解析extension，获取设备的状态

![image-20231206204803506](assets/image-20231206204803506.png)

格式规范文档： https://source.android.com/docs/security/features/keystore/attestation#attestation-extension 

简单看下解析extension的内容

![image-20231206205018254](assets/image-20231206205018254.png)

解析后部分数据

```agsl
Attest version: Keymaster version 4.1
Attest security: StrongBox
Verified boot Key: AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA= (base64)
Device locked: false
Verified boot state: Unverified

//Hash for boot
//Hashtree metadata for system
//Hashtree metadata for vendor
Verified boot hash: nDqAWissOCsw+aWEm7cEcAkCvQngEE+ypQ75UWakxt4= (base64) 
```

## 饶过手段

思路比较简单，替换到整条证书链为一个正常设备的证书链即可：

1. 可以通过hook java层代码
2. 写一个magisk插件 https://github.com/doom-man/bypasskeyattestation



hook java层已经比较熟练了，由于后续期望强化对异常设备的检测，大多对抗检测的工具又是走magisk插件实现的，打算用magisk插件实现一遍。

参考 https://github.com/chiteroman/PlayIntegrityFix 大佬写的插件进行学习，对大佬拙劣的模仿。



### 准备证书

将证书文件移动/data/local/tmp 下，并提供读权限；

![image-20231206205854947](assets/image-20231206205854947.png)

### 注入目标进程

代码入口在cpp/main.cpp 

![image-20231206210101742](assets/image-20231206210101742.png)

![image-20231206210830493](assets/image-20231206210830493.png)

### 替换证书链

![image-20231206210430273](assets/image-20231206210430273.png)

CustomKeyStoreSpi.java 

![image-20231206210320245](assets/image-20231206210320245.png)

替换后效果

<img src="assets/image-20231206210517186.png" alt="image-20231206210517186" style="zoom:30%;" />