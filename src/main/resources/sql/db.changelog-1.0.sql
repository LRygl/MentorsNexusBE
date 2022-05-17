--liquibase formatted sql

--changeset lrygl:1

/* CREATE DATABASE */

CREATE EXTENSION IF NOT EXISTS "uuid-ossp";

DROP TABLE IF EXISTS application_users CASCADE;
DROP TABLE IF EXISTS course CASCADE;
DROP TABLE IF EXISTS user_courses CASCADE;
DROP TABLE IF EXISTS lesson CASCADE;
DROP TABLE IF EXISTS course_lesson CASCADE;
DROP TABLE IF EXISTS course_category CASCADE;

CREATE TABLE IF NOT EXISTS application_users(
    id SERIAL CONSTRAINT application_users_pk PRIMARY KEY,
    first_name VARCHAR(100),
    last_name VARCHAR(100),
    username VARCHAR(100),
    password VARCHAR(100),
    email VARCHAR(100),
    company VARCHAR(100),
    profileImageUrl VARCHAR(100),
    lastLoginDate DATE,
    lastLoginDateDisplay DATE,
    joinDate DATE,
    updatedDate DATE,
    role VARCHAR,
    authorities VARCHAR,
    isActive BOOLEAN,
    isNotLocked BOOLEAN
);

CREATE TABLE IF NOT EXISTS course_category(
    id SERIAL CONSTRAINT course_category_pk PRIMARY KEY NOT NULL,
    categoryName VARCHAR(50) NOT NULL,
    categoryDescription VARCHAR(255) NOT NULL,
    categoryCreated DATE NOT NULL,
    categoryUpdated DATE,
    categoryActive BOOLEAN
);

CREATE TABLE IF NOT EXISTS course(
    id SERIAL CONSTRAINT course_pk PRIMARY KEY,
    courseId uuid DEFAULT uuid_generate_v4() NOT NULL,
    courseName VARCHAR(255) NOT NULL,
    courseDescription VARCHAR(255) NOT NULL,
    courseOwnerId int NOT NULL,
    courseCategoryId int NOT NULL,
    courseCreatedDate DATE NOT NULL,
    coursePublishedDate DATE NOT NULL,
    courseIsPublished BOOLEAN,
    courseIsPrivate BOOLEAN,

    FOREIGN KEY (courseOwnerId) REFERENCES application_users(id),
    FOREIGN KEY (courseCategoryId) REFERENCES course_category(id)
);



CREATE TABLE user_courses(
    id SERIAL NOT NULL CONSTRAINT user_course_pk PRIMARY KEY,
    userId int NOT null,
    courseId int NOT NULL,
    dateJoined date NOT null,

    FOREIGN KEY (userId) REFERENCES application_users(id),
    FOREIGN KEY (courseId) REFERENCES course(id)
);

CREATE TABLE lesson(
    id SERIAL NOT NULL CONSTRAINT lesson_pk PRIMARY KEY,
    lessonId UUID NOT NULL,
    lessonName VARCHAR(255) NOT NULL,
    lessonDescription VARCHAR(255) NOT NULL,
    lessonCreated DATE NOT NULL,
    lessonUpdated DATE NOT NULL,
    lessonSourceDataUrl VARCHAR(255) NOT NULL
);

CREATE TABLE course_lesson(
    id SERIAL NOT NULL CONSTRAINT course_lesson_pk PRIMARY KEY,
    courseId int NOT NULL,
    lessonId int NOT NULL,
    dateAded date NOT NULL,

    FOREIGN KEY (courseId) REFERENCES course(id),
    FOREIGN KEY (lessonId) REFERENCES lesson(id)
);



/* INSERTS */
INSERT INTO course_category VALUES
    (DEFAULT,'EXCEL','Kurzy excelu','2022-06-01','2022-06-01',true),
    (DEFAULT,'PostgreSQL','Kurzy PostgreSQL','2022-06-01','2022-06-01',true),
    (DEFAULT,'POSTMAN','Kurzy POSTMAN','2022-06-01','2022-06-01',true),
    (DEFAULT,'VBA','Kurzy VBA','2022-06-01','2022-06-01',true),
    (DEFAULT,'BMPN','Kurzy BMPN','2022-06-01','2022-06-01',true),
    (DEFAULT,'JAVA','Kurzy JAVA','2022-06-01','2022-06-01',true);

insert into APPLICATION_USERS values
    (default,'Lubomír','Rýgl','lordxray','123','lrygl@gmail.com','Mentors.cz','123','2022-06-01','2022-06-01','2022-06-01','2022-06-01','test','test',true,true);

INSERT INTO course VALUES
    (DEFAULT,uuid_generate_v4(),'EXCEL PRO ZAČÁTEČNÍKY','Lorem ipsum dolor sit amet',1,1,'2022-06-01','2022-06-01',true,false),
    (DEFAULT,uuid_generate_v4(),'EXCEL PRO STŘEDNĚ POKROČILÉ','Lorem ipsum dolor sit amet',1,1,'2022-06-01','2022-06-01',true,false),
    (DEFAULT,uuid_generate_v4(),'POSTMAN A API PRO ZAČÁTEČNÍKY','Lorem ipsum dolor sit amet',1,3,'2022-06-01','2022-06-01',true,false),
    (DEFAULT,uuid_generate_v4(),'POSTGRESQL PRO ZAČÁTEČNÍKY','Lorem ipsum dolor sit amet',1,2,'2022-06-01','2022-06-01',true,false);

insert into user_courses values
    (DEFAULT,1,1,'2022-06-01'),
    (DEFAULT,1,2,'2022-06-01'),
    (DEFAULT,1,3,'2022-06-01'),
    (DEFAULT,1,4,'2022-06-01');


INSERT INTO lesson VALUES
    (DEFAULT,uuid_generate_v4(),'Představení kurzu','Lorem ipsum dolor sit amet','2022-06-01','2022-06-01','/baseUrl/Data/Lesson/01/Data/Vide/Source'),
    (DEFAULT,uuid_generate_v4(),'Prostředí aplikace MS Excel','Lorem ipsum dolor sit amet','2022-06-01','2022-06-01','/baseUrl/Data/Lesson/01/Data/Vide/Source'),
    (DEFAULT,uuid_generate_v4(),'Možnosti aplikace MS Excel','Lorem ipsum dolor sit amet','2022-06-01','2022-06-01','/baseUrl/Data/Lesson/01/Data/Vide/Source'),
    (DEFAULT,uuid_generate_v4(),'Zdrojové soubory a cvičení','Lorem ipsum dolor sit amet','2022-06-01','2022-06-01','/baseUrl/Data/Lesson/01/Data/Vide/Source'),
    (DEFAULT,uuid_generate_v4(),'Listy, sešity a buňky','Lorem ipsum dolor sit amet','2022-06-01','2022-06-01','/baseUrl/Data/Lesson/01/Data/Vide/Source'),
    (DEFAULT,uuid_generate_v4(),'Buňky a pohyb v aplikaci','Lorem ipsum dolor sit amet','2022-06-01','2022-06-01','/baseUrl/Data/Lesson/01/Data/Vide/Source'),
    (DEFAULT,uuid_generate_v4(),'Sloupce, řádky a práce s nimi','Lorem ipsum dolor sit amet','2022-06-01','2022-06-01','/baseUrl/Data/Lesson/01/Data/Vide/Source'),
    (DEFAULT,uuid_generate_v4(),'Formátování a ohraničení','Lorem ipsum dolor sit amet','2022-06-01','2022-06-01','/baseUrl/Data/Lesson/01/Data/Vide/Source'),
    (DEFAULT,uuid_generate_v4(),'Úvod do kurzu','Lorem ipsum dolor sit amet','2022-06-01','2022-06-01','/baseUrl/Data/Lesson/01/Data/Vide/Source'),
    (DEFAULT,uuid_generate_v4(),'Co je to API','Lorem ipsum dolor sit amet','2022-06-01','2022-06-01','/baseUrl/Data/Lesson/01/Data/Vide/Source'),
    (DEFAULT,uuid_generate_v4(),'Instalace aplikace','Lorem ipsum dolor sit amet','2022-06-01','2022-06-01','/baseUrl/Data/Lesson/01/Data/Vide/Source'),
    (DEFAULT,uuid_generate_v4(),'Úživatelské rozhraní','Lorem ipsum dolor sit amet','2022-06-01','2022-06-01','/baseUrl/Data/Lesson/01/Data/Vide/Source'),
    (DEFAULT,uuid_generate_v4(),'Kolekce, environment a proměnné','Lorem ipsum dolor sit amet','2022-06-01','2022-06-01','/baseUrl/Data/Lesson/01/Data/Vide/Source');

INSERT INTO course_lesson VALUES
    (DEFAULT,1,1,'2022-06-01'),
    (DEFAULT,1,2,'2022-06-01'),
    (DEFAULT,1,3,'2022-06-01'),
    (DEFAULT,1,4,'2022-06-01'),
    (DEFAULT,1,5,'2022-06-01'),
    (DEFAULT,1,6,'2022-06-01'),
    (DEFAULT,1,7,'2022-06-01'),
    (DEFAULT,1,8,'2022-06-01'),
    (DEFAULT,3,9,'2022-06-01'),
    (DEFAULT,3,10,'2022-06-01'),
    (DEFAULT,3,11,'2022-06-01'),
    (DEFAULT,3,12,'2022-06-01'),
    (DEFAULT,3,13,'2022-06-01');



/* SELECTS */

SELECT * FROM application_users au ;
SELECT * FROM course c;
SELECT * FROM course_lesson cl;
SELECT * FROM user_courses uc;
SELECT * FROM lesson l;
SELECT * FROM course_category cc;

SELECT courseName,first_name,last_name from user_courses
    join application_users au on user_courses.userId = au.id
    join course c on user_courses.courseId = c.id
WHERE au.id=1;

select c.id as courseId,courseName as courseName,lessonName as LessonName, cc.categoryName from course_lesson
    join lesson l on course_lesson.lessonId = l.id
    join course c on course_lesson.courseId = c.id
    join course_category cc on c.coursecategoryId = cc.id;
