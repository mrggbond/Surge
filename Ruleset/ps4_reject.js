// Surge Script
// 这段脚本检查源 IP 和多个 CIDR，并拒绝匹配的请求。

const REJECT = 'REJECT';

// 定义要检查的条件
const srcIp = '192.168.32.102';
const cidrIps = [
    '2.16.168.103/32',
    '2.16.168.112/32',
    '2.17.57.196/32',
    '2.18.148.58/32',
    '23.35.185.187/32',
    '23.41.27.237/32',
    '23.42.176.57/32',
    '23.56.109.138/32',
    '23.56.109.141/32',
    '23.56.190.65/32',
    '23.195.119.70/32',
    '23.195.119.89/32',
    '23.215.161.108/32',
    '23.217.197.76/32',
    '23.218.30.189/32',
    '23.218.109.95/32',
    '23.222.110.163/32',
    '100.42.96.33/32',
    '104.142.254.227/32',
    '184.26.172.230/32',
    '184.28.247.231/32'
]; // 可以在这里添加多个 CIDR

// 获取请求信息
let request = $request;

// 提取源 IP 和目标 IP
let sourceIp = request.ip; // 假设 Surge 提供了请求的源 IP
let targetIp = request.hostname; // 假设目标 IP 可以通过 host 获取

// 检查条件
if (sourceIp === srcIp && cidrIps.every(cidr => isIpInCIDR(targetIp, cidr))) {
    $done({ response: { status: 403, body: 'Access Denied' } }); // 拒绝访问
} else {
    $done(); // 继续处理请求
}

// 辅助函数：检查 IP 是否在 CIDR 范围内
function isIpInCIDR(ip, cidr) {
    const [cidrBase, cidrMask] = cidr.split('/');
    const ipBinary = ipToBinary(ip);
    const cidrBinary = ipToBinary(cidrBase);
    
    const mask = (1 << (32 - cidrMask)) - 1;
    return (ipBinary & ~mask) === (cidrBinary & ~mask);
}

// 辅助函数：将 IP 转换为二进制
function ipToBinary(ip) {
    return ip.split('.').reduce((acc, octet) => (acc << 8) + parseInt(octet, 10), 0) >>> 0;
}
