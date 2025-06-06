FROM ghcr.io/zhangbin0301/abcdxhttp:latest

ENV PORT 7860

RUN chmod 777 /app

USER 10014
