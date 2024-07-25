# Create and run container
sudo docker run --name alp-1 -it alp 

# Start container
sudo docker start -i alp-1

# Run python server
python3 -m http.server