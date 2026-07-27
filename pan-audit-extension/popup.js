document.getElementById("openDashboard").addEventListener("click", () => {
  chrome.tabs.create({ url: chrome.runtime.getURL("dashboard.html") });
});
document.getElementById("openConnections").addEventListener("click", () => {
  chrome.runtime.openOptionsPage();
});
