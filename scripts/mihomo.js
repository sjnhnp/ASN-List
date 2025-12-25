import fs from 'fs';
import path from 'path';
import { exec } from 'child_process';

// 获取 base_dir 环境变量
const baseDir = process.env.base_dir;
// 设置最大重试次数
const maxRetries = 3;
// 设置重试间隔（单位：毫秒）
const retryInterval = 5000;

// 如果没有设置 base_dir 环境变量，则终止程序并提示错误
if (!baseDir) {
  console.error('Error: base_dir 环境变量未设置');
  process.exit(1);
}

/**
 * 递归读取目录中的所有 *_IP.yaml 文件
 * 注意：mihomo convert-ruleset 只支持 domain 和 ipcidr 类型，不支持 classical 类型
 * 因此 ASN 规则（classical behavior）无法转换为 .mrs 格式
 */
const findFiles = (dir) => {
  let results = [];
  const files = fs.readdirSync(dir);

  files.forEach((file) => {
    const fullPath = path.join(dir, file);
    const stat = fs.statSync(fullPath);

    if (stat && stat.isDirectory()) {
      results = [...results, ...findFiles(fullPath)];
    } else if (file.endsWith('_IP.yaml')) {
      // 只处理 IP CIDR 文件，ASN 文件无法转换为 mrs 格式
      results.push(fullPath);
    }
  });

  return results;
};

// 执行命令的封装，支持重试机制
const executeCommand = async (cmd, retries = 0) => {
  return new Promise((resolve, reject) => {
    exec(cmd, (error, stdout, stderr) => {
      if (error) {
        console.error(`命令执行失败: ${cmd}`);
        console.error(`Stderr: ${stderr}`);
        if (retries < maxRetries) {
          console.log(`正在重试... (第 ${retries + 1} 次)`);
          setTimeout(() => resolve(executeCommand(cmd, retries + 1)), retryInterval);
        } else {
          reject(new Error(`命令执行失败: ${cmd}, Stderr: ${stderr}`));
        }
      } else {
        resolve(stdout);
      }
    });
  });
};

const processFiles = async () => {
  const files = findFiles(baseDir);
  console.log(`找到 ${files.length} 个 IP CIDR 文件需要转换`);

  for (const srcFile of files) {
    const targetFile = srcFile.replace('.yaml', '.mrs');
    const command = `mihomo convert-ruleset ipcidr yaml "${srcFile}" "${targetFile}"`;

    try {
      await executeCommand(command);
      console.log(`转换成功: ${srcFile} -> ${targetFile}`);
    } catch (error) {
      console.log(`转换失败: ${srcFile} -> ${targetFile}，已达到最大重试次数`);
      console.error(`Error message: ${error.message}`);
    }
  }
};

// 执行文件处理
processFiles();
