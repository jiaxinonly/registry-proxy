FROM python:3.13.5-slim

# 设置工作目录
WORKDIR /app

# 复制程序
COPY app .

# 安装依赖
RUN pip config set global.index-url https://mirrors.aliyun.com/pypi/simple/ && pip install --upgrade pip && pip install --no-cache-dir -r requirements.txt

# 暴露端口（根据你的应用调整）
EXPOSE 80 443

# 运行命令
CMD ["python", "main.py"]