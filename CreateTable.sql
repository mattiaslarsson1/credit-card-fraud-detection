--Author: [Jacky Chan]
--Assignment# 2 / Part 3 (etc.)
--Date due: March 8,2026 
--I pledge that I have completed this assignment without collaborating
--with anyone else, in conformance with the NYU School of Engineering
--Policies and Procedures on Academic Misconduct.

--q1
ALTER TABLE room 
MODIFY COLUMN roomtype CHAR(1) SET DEFAULT 'N';

--q2
ALTER TABLE hotel
ADD COLUMN hotelphone VARCHAR(15);

--q3
ALTER TABLE guest
ADD COLUMN guestemail VARCHAR(25);

--q4
ALTER TABLE hotel
MODIFY COLUMN hotelname VARCHAR(35);