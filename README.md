# Cats vs Dogs website
#### Video Demo:  https://youtu.be/wgZmhAmpltw
#### Description:
The Goal of my website was to answer the age old question which is better: Cats or Dogs. After lots of time spent pondering this question I realised that to find out which is better you must go to the domain of animals, social media. Cats vs Dogs is the website that aims to finish this question by posting and liking photos of cats and dogs till one comes on top.

Static
This is where all of the images and the stylesheet for the website are contained. Going from the top, the Cats vs Dogs.png is the main photo for the website designed in ms paint. I wanted this photo to give the feel of early internet meme fights through the images and the vs in the middle. Next up, I used the website shown in the finance project to get a favicon of a cat for the icon. I chose a Cat because it is more widely used on the internet and it is the first in the name Cats vs Dogs, this choice does not reflect a bias from me. With like.png and Red_X.png both are images I found on the internet and then resized to be smaller file sizes to get them to load faster and fit on the screen better. Last in the static folder is styles.css this was definitely where most of my pain came from in the project as css never fully cooperated with me. The first 6 definitions are all for the nav bar at the top of the website which give it its highlighted feature and all of the centering. The rest of the definitions are all for the body of the website defining the style of the posts, images and help with the various centering for the posts.

Templates
To start with the templates the most important is layout.html which is very simple. Most of the code here is based off of work done by me in the finance project. Getting to the exciting stuff home.html is definitely the largest and has the most going on in its code. At the top is the image and then it shows which animal is winning. This part took me a while to figure out how to use the dictionaries to give the total number but I will get more into that when I get into app.py. Using ninja the website displays which animal is winning or if there is a tie between them. The next part of home.html is the for loop for each post which starts with the divs that give the box and the style to the post then of course the image. The if statement following the image checks if the user is an admin and then gives them an all powerful x mark that can delete posts that don’t follow the simple rules of the website (Photo of cat or dog). I wanted this because most social media have bad moderation and I wanted to avoid this problem by having the website be easy to moderate. The next part is a failed feature that would show if an image is liked or not, I am on a time constraint but I at least wanted to leave it in the code if I wanted to fix it in future. Login post and register .html are all pretty similar giving an input box the main difference is that post has a "<select>" that allows 3 different inputs for what animal is in the post. However if “other” is selected then it returns an apology. Speaking of apologies, the last file in templates is apology.html which has the same system as finances apologies.

Going outside of the file folders is app.py database.db and helpers.py. I will only describe the first two because the helpers.py is just certain code segments taken from finance

App.py
The first part of the file is of course the prerequisites like flask, sql and all of the helpers. The first app.route is home which requires login of course. If the method is GET then it will check if your user_id is 1 which means you are the admin and then gives you privileges in home.html. The next part is also for the cut part of code that gives colour if a post was already liked then, the total amount of likes for cats and dogs are compiled and then the template is rendered. If the request method was post it checks whether the user is trying to delete a post or like a post. If they are deleting the records of that post are deleted from the images and like tables which will be elaborated on later. If the user was trying to like an image it checks if the user has already liked the image and then updates the databases. The next app route is post and primarily is checking if the post follows the basic needs like an image address which is what this website uses for photos and what animal it is. The next three routes login register and logout are pretty similar to stuff shown in finance and I am not sure of where exactly the differences lie.

Database.db
The main 3 tables are users, images and like. To start the users table uses the hash I learnt in the finance project to encrypt the pass code and also includes the users auto incrementing id and their username. The id is very important because the user with id “1” had admin privileges. Secondly, the images table differs from the previous in its image address and the animal it values. The animal value will always be “cat” or “dog”  and app.py will never give another value. And the last part of the website is the like table which just contains the image_id and the user_id and is used to make sure a user doesn’t like something more than once. The database file has probably been the file with the most iterations and in previous versions there has been many other now gone tables and rows in those tables.