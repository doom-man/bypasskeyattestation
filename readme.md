# bypassKeyAttestation

饶过密钥认证

## 使用流程
1. magisk 安装bypassKeyAttestation模块
2. 配置排除列表，选中目标apk
3. 关闭“遵守排除列表(Enforce DenyList)”
4. 重启手机


如果遇到问题，关闭改其他所有模块, 重启。

## 
尝试欺骗key attestation生成证书时 application_id和signatures 的数据，实际数据不是通过目标应用的接口去生成的，当前情况无法导出证书。


> https://bbs.kanxue.com/thread-279799.htm
