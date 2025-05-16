// Surge Script
// 这段脚本检查源 IP 和多个 CIDR，并拒绝匹配的请求。

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
];

// 检查匹配条件
var sourceIp = $request.sourceIP; // 获取请求的源 IP
var isMatched = false;

// 检查源 IP 是否匹配
if (sourceIp === '192.168.32.102') { // 源 IP
    // 检查目标是否在 CIDR 列表中
    isMatched = cidrIps.every(cidr => isIpInCIDR($request.hostname, cidr));
}

// 返回匹配结果
$done({ matched: isMatched });

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
