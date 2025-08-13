FROM python:alpine
ENV HOST=0.0.0.0
ENV PORT=58008
WORKDIR /backend
COPY /backend .
RUN pip install --no-cache-dir --no-color -U -r requirements.txt
EXPOSE 58008
CMD ["python", "main.py"]
LABEL org.opencontainers.image.source=https://github.com/Elektron-blip/relay