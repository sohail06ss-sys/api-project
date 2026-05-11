const API_BASE = window.location.origin;

function showDashboard(){

    document.getElementById("authScreen")
    .classList.add("hidden");

    document.getElementById("dashboardScreen")
    .classList.remove("hidden");
}

function showAuth(){

    document.getElementById("dashboardScreen")
    .classList.add("hidden");

    document.getElementById("authScreen")
    .classList.remove("hidden");
}

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

function googleLogin(){

    localStorage.removeItem("token");

    window.location.href =
    `${API_BASE}/google_login`;
}

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

    document.getElementById("currentUser")
    .innerText = user.name;

    document.getElementById("profileName")
    .innerText = user.name;

    document.getElementById("profileEmail")
    .innerText = user.email;

    document.getElementById("profileRole")
    .innerText = `Role: ${user.role}`;

    document.getElementById("profileMobile")
    .innerText = `Mobile: ${user.mobile}`;

    if(user.picture){

        document.getElementById("profileImage")
        .src = user.picture;
    }

    // ADMIN PANEL

    if(user.role === "Admin"){

        document.getElementById("adminPanel")
        .classList.remove("hidden");

        loadUsers();
    }

    showDashboard();
}

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

    table.innerHTML = "";

    users.forEach(user => {

        table.innerHTML += `

        <tr>

            <td>${user.id}</td>

            <td>${user.name}</td>

            <td>${user.email}</td>

            <td>${user.role}</td>

            <td>${user.mobile}</td>

            <td>

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

            mobile:document.getElementById("newUserMobile").value
        })
    });

    const data = await res.json();

    alert(data.message || data.error);

    loadUsers();
}

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

function logoutUser(){

    localStorage.removeItem("token");

    document.getElementById("profileImage")
    .src = "https://i.imgur.com/6VBx3io.png";

    document.getElementById("adminPanel")
    .classList.add("hidden");

    showAuth();

    window.history.replaceState(
        {},
        document.title,
        "/"
    );
}

function forgotPassword(){

    alert(
        "Forgot password backend route will be added next."
    );
}

// GOOGLE LOGIN TOKEN

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

// INITIAL LOAD

loadCurrentUser();