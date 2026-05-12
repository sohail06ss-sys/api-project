const API_BASE = window.location.origin;

// ---------------- UI ----------------

function showDashboard(){

    const auth =
    document.getElementById("authScreen");

    const dashboard =
    document.getElementById("dashboardScreen");

    auth.style.display = "none";

    dashboard.style.display = "block";

    dashboard.classList.remove("hidden");
}

function showAuth(){

    const auth =
    document.getElementById("authScreen");

    const dashboard =
    document.getElementById("dashboardScreen");

    dashboard.style.display = "none";

    auth.style.display = "flex";

    auth.classList.remove("hidden");
}

// ---------------- REGISTER ----------------

async function registerUser(){

    localStorage.removeItem("token");

    const res = await fetch(`${API_BASE}/register`,{

        method:"POST",

        headers:{
            "Content-Type":"application/json"
        },

        body:JSON.stringify({

            name:document.getElementById("name").value,

            email:document.getElementById("email").value,

            password:document.getElementById("password").value,

            mobile:document.getElementById("mobile").value
        })
    });

    const data = await res.json();

    alert(data.message || data.error);
}

// ---------------- LOGIN ----------------

async function loginUser(){

    const res = await fetch(`${API_BASE}/login`,{

        method:"POST",

        headers:{
            "Content-Type":"application/json"
        },

        body:JSON.stringify({

            email:document.getElementById("email").value,

            password:document.getElementById("password").value
        })
    });

    const data = await res.json();

    if(data.token){

        localStorage.setItem("token",data.token);

        await loadCurrentUser();

        showDashboard();

    }else{

        alert(data.error || "Login Failed");
    }
}

// ---------------- GOOGLE LOGIN ----------------

function googleLogin(){

    localStorage.removeItem("token");

    window.location.href =
    `${API_BASE}/google_login`;
}

// ---------------- CURRENT USER ----------------

async function loadCurrentUser(){

    const token =
    localStorage.getItem("token");

    if(!token){

        showAuth();
        return;
    }

    const res = await fetch(`${API_BASE}/me`,{

        headers:{
            Authorization:`Bearer ${token}`
        }
    });

    if(!res.ok){

        logoutUser();
        return;
    }

    const user = await res.json();

    const currentUser =
    document.getElementById("currentUser");

    if(currentUser){
        currentUser.innerText = user.name;
    }

    const profileName =
    document.getElementById("profileName");

    if(profileName){
        profileName.innerText = user.name;
    }

    const profileEmail =
    document.getElementById("profileEmail");

    if(profileEmail){
        profileEmail.innerText = user.email;
    }

    const profileRole =
    document.getElementById("profileRole");

    if(profileRole){
        profileRole.innerText = `Role: ${user.role}`;
    }

    const profileMobile =
    document.getElementById("profileMobile");

    if(profileMobile){
        profileMobile.innerText =
        `Mobile: ${user.mobile}`;
    }

    if(user.picture){

        const profileImage =
        document.getElementById("profileImage");

        if(profileImage){
            profileImage.src = user.picture;
        }
    }

    if(user.role === "Admin"){

        const adminPanel =
        document.getElementById("adminPanel");

        if(adminPanel){
            adminPanel.classList.remove("hidden");
        }

        loadUsers();
    }

    showDashboard();
}

// ---------------- LOAD USERS ----------------

async function loadUsers(){

    const token =
    localStorage.getItem("token");

    const res = await fetch(`${API_BASE}/users`,{

        headers:{
            Authorization:`Bearer ${token}`
        }
    });

    const users = await res.json();

    const table =
    document.getElementById("usersTable");

    if(!table) return;

    table.innerHTML = "";

    users.forEach(user => {

        table.innerHTML += `

        <tr>

            <td>${user.id}</td>

            <td>
                <input
                    value="${user.name}"
                    id="name-${user.id}">
            </td>

            <td>
                <input
                    value="${user.email}"
                    id="email-${user.id}">
            </td>

            <td>

                <select id="role-${user.id}">

                    <option
                        value="User"
                        ${user.role === "User" ? "selected" : ""}>

                        User

                    </option>

                    <option
                        value="Admin"
                        ${user.role === "Admin" ? "selected" : ""}>

                        Admin

                    </option>

                </select>

            </td>

            <td>
                <input
                    value="${user.mobile}"
                    id="mobile-${user.id}">
            </td>

            <td>

                <button
                    onclick="updateUser(${user.id})"
                    class="btn primary small">

                    Save

                </button>

                <button
                    onclick="deleteUser(${user.id})"
                    class="btn danger small">

                    Delete

                </button>

            </td>

        </tr>
        `;
    });
}

// ---------------- ADD USER ----------------

async function addUser(){

    const token =
    localStorage.getItem("token");

    const res = await fetch(`${API_BASE}/users`,{

        method:"POST",

        headers:{
            "Content-Type":"application/json",
            Authorization:`Bearer ${token}`
        },

        body:JSON.stringify({

            name:document.getElementById("newUserName").value,

            email:document.getElementById("newUserEmail").value,

            mobile:document.getElementById("newUserMobile").value,

            role:document.getElementById("newUserRole").value
        })
    });

    const data = await res.json();

    alert(data.message || data.error);

    loadUsers();
}

// ---------------- UPDATE USER ----------------

async function updateUser(id){

    const token =
    localStorage.getItem("token");

    const res = await fetch(`${API_BASE}/users/${id}`,{

        method:"PUT",

        headers:{
            "Content-Type":"application/json",
            Authorization:`Bearer ${token}`
        },

        body:JSON.stringify({

            name:document.getElementById(`name-${id}`).value,

            email:document.getElementById(`email-${id}`).value,

            mobile:document.getElementById(`mobile-${id}`).value,

            role:document.getElementById(`role-${id}`).value
        })
    });

    const data = await res.json();

    alert(data.message || data.error);

    loadUsers();
}

// ---------------- DELETE USER ----------------

async function deleteUser(id){

    const token =
    localStorage.getItem("token");

    await fetch(`${API_BASE}/users/${id}`,{

        method:"DELETE",

        headers:{
            Authorization:`Bearer ${token}`
        }
    });

    loadUsers();
}

// ---------------- WEATHER ----------------

async function searchWeather(){

    const city =
    document.getElementById("cityInput").value;

    if(!city){

        alert("Enter city name");
        return;
    }

    try{

        const res = await fetch(
            `https://wttr.in/${city}?format=j1`
        );

        const data = await res.json();

        const current =
        data.current_condition[0];

        document.getElementById("temp")
        .innerText =
        `${current.temp_C}°`;

        document.getElementById("weatherType")
        .innerText =
        current.weatherDesc[0].value;

        document.getElementById("feelsLike")
        .innerText =
        `Feels Like: ${current.FeelsLikeC}°`;

        document.getElementById("humidity")
        .innerText =
        `${current.humidity}%`;

        document.getElementById("windSpeed")
        .innerText =
        `${current.windspeedKmph} km/h`;

        document.getElementById("pressure")
        .innerText =
        `${current.pressure} mb`;

        document.getElementById("visibility")
        .innerText =
        `${current.visibility} km`;

        const condition =
        current.weatherDesc[0].value.toLowerCase();

        let icon = "☀️";

        if(condition.includes("rain")){
            icon = "🌧️";
        }
        else if(condition.includes("cloud")){
            icon = "☁️";
        }
        else if(condition.includes("snow")){
            icon = "❄️";
        }
        else if(condition.includes("storm")){
            icon = "⛈️";
        }

        document.getElementById("weatherIcon")
        .innerText = icon;

        const forecastContainer =
        document.getElementById("forecastContainer");

        forecastContainer.innerHTML = "";

        data.weather.forEach(day => {

            forecastContainer.innerHTML += `

            <div class="forecast-card">

                <h4>${day.date}</h4>

                <p>🌡 ${day.avgtempC}°</p>

                <p>💧 ${day.hourly[0].humidity}%</p>

                <p>
                    ${day.hourly[0].weatherDesc[0].value}
                </p>

            </div>
            `;
        });

    }catch(err){

        alert("Weather fetch failed");
    }
}

// ---------------- AI ASSISTANT ----------------

async function askAI(){

    const prompt =
    document.getElementById("aiPrompt").value;

    if(!prompt){

        alert("Enter your question");
        return;
    }

    const token =
    localStorage.getItem("token");

    const responseBox =
    document.getElementById("aiResponse");

    responseBox.innerHTML =
    "Thinking...";

    try{

        const res = await fetch(
            `${API_BASE}/ai`,
            {

                method:"POST",

                headers:{
                    "Content-Type":"application/json",
                    Authorization:`Bearer ${token}`
                },

                body:JSON.stringify({
                    prompt:prompt
                })
            }
        );

        const data = await res.json();

        responseBox.innerHTML =
        data.reply || data.error;

    }catch(err){

        responseBox.innerHTML =
        "AI request failed";
    }
}

// ---------------- LOGOUT ----------------

function logoutUser(){

    localStorage.removeItem("token");

    const profileImage =
    document.getElementById("profileImage");

    if(profileImage){

        profileImage.src =
        "https://i.imgur.com/6VBx3io.png";
    }

    const adminPanel =
    document.getElementById("adminPanel");

    if(adminPanel){
        adminPanel.classList.add("hidden");
    }

    showAuth();

    window.history.replaceState(
        {},
        document.title,
        "/"
    );

    window.location.href =
    `${API_BASE}/google_logout`;
}

// ---------------- FORGOT PASSWORD ----------------

function forgotPassword(){

    alert(
        "Forgot password backend route will be added next."
    );
}

// ---------------- GOOGLE TOKEN ----------------

const params =
new URLSearchParams(window.location.search);

const token = params.get("token");

if(token){

    localStorage.setItem("token",token);

    window.history.replaceState(
        {},
        document.title,
        "/"
    );
}

// ---------------- INITIAL LOAD ----------------

loadCurrentUser();