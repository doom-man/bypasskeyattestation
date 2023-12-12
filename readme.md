# bypassKeyAttestation

饶过密钥认证

## 使用流程
1. magisk 安装bypassKeyAttestation模块
2. 配置排除列表，选中目标apk
3. 关闭“遵守排除列表(Enforce DenyList)”
4. 重启手机


如果遇到问题，关闭改其他所有模块, 重启。

## todo
1. 尝试修复challenge, 需要真机实时去响应返回证书，我认为这是最完美的饶过手段，明确捕获设置challenge的时机,另一端生成证书，root获取证书.
2. 尝试饶过play integrity


> https://bbs.kanxue.com/thread-279799.htm