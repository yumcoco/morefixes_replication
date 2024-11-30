#!/bin/bash
# 切换到脚本所在目录
cd $(dirname "$0")

# 激活 Conda 环境（将 "prospector_env" 替换为您的 Conda 环境名称）
source "$(conda info --base)/etc/profile.d/conda.sh"
conda activate prospector

# 执行目标 Python 脚本
timeout 3000 python3 cli/main.py "$@"

# 如果需要，还可以直接运行以下行以替代上面的 timeout 行
# python3 cli/main.py "$@"
