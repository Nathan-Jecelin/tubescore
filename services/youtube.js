const API_KEY = process.env.YOUTUBE_API_KEY;
const BASE_URL = 'https://www.googleapis.com/youtube/v3';

function extractVideoId(url) {
  const patterns = [
    /(?:youtube\.com\/watch\?v=)([a-zA-Z0-9_-]{11})/,
    /(?:youtu\.be\/)([a-zA-Z0-9_-]{11})/,
    /(?:youtube\.com\/embed\/)([a-zA-Z0-9_-]{11})/,
    /(?:youtube\.com\/shorts\/)([a-zA-Z0-9_-]{11})/,
  ];

  for (const pattern of patterns) {
    const match = url.match(pattern);
    if (match) return match[1];
  }
  return null;
}

async function getVideoData(videoId) {
  const url = `${BASE_URL}/videos?part=snippet,statistics,contentDetails&id=${videoId}&key=${API_KEY}`;
  const res = await fetch(url);

  if (!res.ok) {
    const err = await res.json().catch(() => ({}));
    throw new Error(err.error?.message || `YouTube API error: ${res.status}`);
  }

  const data = await res.json();
  if (!data.items || data.items.length === 0) {
    throw new Error('Video not found. It may be private or deleted.');
  }

  const video = data.items[0];
  return {
    id: video.id,
    title: video.snippet.title,
    description: video.snippet.description,
    tags: video.snippet.tags || [],
    publishedAt: video.snippet.publishedAt,
    channelId: video.snippet.channelId,
    channelTitle: video.snippet.channelTitle,
    categoryId: video.snippet.categoryId,
    thumbnails: video.snippet.thumbnails,
    viewCount: parseInt(video.statistics.viewCount || '0'),
    likeCount: parseInt(video.statistics.likeCount || '0'),
    commentCount: parseInt(video.statistics.commentCount || '0'),
    duration: video.contentDetails.duration,
    definition: video.contentDetails.definition,
    caption: video.contentDetails.caption,
  };
}

async function getChannelData(channelId) {
  const url = `${BASE_URL}/channels?part=statistics&id=${channelId}&key=${API_KEY}`;
  const res = await fetch(url);

  if (!res.ok) {
    const err = await res.json().catch(() => ({}));
    throw new Error(err.error?.message || `YouTube API error: ${res.status}`);
  }

  const data = await res.json();
  if (!data.items || data.items.length === 0) {
    throw new Error('Channel not found.');
  }

  const channel = data.items[0];
  return {
    subscriberCount: parseInt(channel.statistics.subscriberCount || '0'),
    videoCount: parseInt(channel.statistics.videoCount || '0'),
    totalViewCount: parseInt(channel.statistics.viewCount || '0'),
  };
}

function parseDuration(iso8601) {
  const match = iso8601.match(/PT(?:(\d+)H)?(?:(\d+)M)?(?:(\d+)S)?/);
  if (!match) return 0;
  const hours = parseInt(match[1] || '0');
  const minutes = parseInt(match[2] || '0');
  const seconds = parseInt(match[3] || '0');
  return hours * 3600 + minutes * 60 + seconds;
}

module.exports = { extractVideoId, getVideoData, getChannelData, parseDuration };
