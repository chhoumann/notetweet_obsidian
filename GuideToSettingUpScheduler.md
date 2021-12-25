# Setting up Twitter Scheduling
## Important!
You will be _self_ -hosting a Node.js Express server along with a Postgres database. 

I will show you how to do this for free.

I will provide you with an existing scheduler, which you can modify it or add improvements to as you please.
If you desire, you could also create it in any way you want - as long as the API endpoints match those set in NoteTweet (which isn't configurable right now; open an issue if you need something). 

This is the repository for the [scheduler](https://github.com/chhoumann/notetweet-scheduler).

Scheduling tweets __requires the Natural Language Dates plugin for Obsidian!__

## Guide
The first thing you will need to do is to deploy the scheduler server. To do so, first click the ``Deploy`` button.

[![Deploy](https://www.herokucdn.com/deploy/button.svg)](https://heroku.com/deploy?template=https://github.com/chhoumann/notetweet-scheduler)

If you do not already have an account for Heroku, go ahead and sign up.

You should now see a page such as this one:

![image](https://user-images.githubusercontent.com/29108628/124105913-fb707200-da63-11eb-8d16-27b507d0ddca.png)

On this page, follow these steps:
1. Set an app name.
2. Choose the region closest to you.
3. Set the `ACCESS_SECRET`, `ACCESS_TOKEN`, `API_KEY`, and `API_SECRET`. These are the ones you've already set up to get NoteTweet working. If you are in Secure Mode, you _cannot_ simply copy the keys over - they are encrypted. Get the plain ones you got from Twitter (you can disable Secure mode, copy them over, and enable it again).
4. Set the `Origin` to `https://<YOUR_APP_NAME>.herokuapp.com`, where `<YOUR_APP_NAME>` should be replaced by the name of your app that you specified in (1). Save this somewhere, you'll need it in a bit.
5. Set a password for your scheduler. Anyone with this password can tweet on your behalf, so make it secure. And I'd also recommend that it isn't your Twitter password.
6. Click 'Deploy app' and wait for it to deploy.

Now, go back into your NoteTweet settings. Here, you should
1. Set `Scheduler URL` to the same as `Origin` - the one you saved in (4).
2. Set `Scheduler password` to the password you specified in (5).

Now you're ready to schedule tweets!

As mentioned, we're leveraging [nldates-obsidian](https://github.com/argenos/nldates-obsidian) to set the dates. This means that you could write `today at 15:30` to post today at 15:30. You can always update this date, or unschedule the tweet, by going into NoteTweet settings and opening the Scheduled tweets menu.
