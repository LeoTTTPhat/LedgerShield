FROM python:3.12-slim

WORKDIR /ledger-shield
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY . .

CMD ["make", "test"]
