build:
	docker build -t oj-backend .

run:
	docker run -p 7778:3000 -dit oj-backend sh run.sh
