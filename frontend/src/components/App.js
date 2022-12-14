/* eslint-disable react-hooks/exhaustive-deps */
import React, { useState, useEffect} from "react";
import { Route, Routes, useNavigate } from "react-router-dom";
import Login from "./Login";
import Register from "./Register";
import ProtectedRoute from "./ProtectedRoute";
import NotFound from "./NotFound";
import Header from "./Header";
import Main from "./Main";
import Footer from "./Footer";
import ImagePopup from "./ImagePopup";
import EditProfilePopup from "./EditProfilePopup";
import EditAvatarPopup from "./EditAvatarPopup";
import AddPlacePopup from "./AddPlacePopup";
import { CurrentUserContext } from "../contexts/CurrentUserContext";
import api from "../utils/api";
import ConfirmPopup from "./ConfirmPopup";

function App() {
  const [isEditProfilePopupOpen, setEditProfilePopupOpen] = useState(false);
  const [isAddPlacePopupOpen, setAddPlacePopupOpen] = useState(false);
  const [isEditAvatarPopupOpen, setEditAvatarPopupOpen] = useState(false);
  const [isConfirmPopupOpen, setConnfirmPopupOpen] = useState(false);
  const [isImagePopupOpen, setImagePopupOpen] = useState(false);
  const [selectedCard, setSelectedCard] = useState(null);
  const [removeCard, setRemoveCard] = useState(null);
  const [currentUser, setCurrentUser] = useState({ name: "", about: "", avatar: "" });
  const [cards, setCards] = useState([]);
  const [email, setEmail] = useState("");
  const [isInfoTooltipOpen, setInfoTooltipOpen] = useState(false);
  const [success, setSuccess] = useState(false);
  const [loggedIn, setLoggedIn] = useState(false);
  const [isLoading, setIsLoading] = useState(false);
  const navigate = useNavigate();

  const handleCardClick = (card) => {
    setImagePopupOpen(true);
    setSelectedCard(card);
  };
  const handleEditAvatarClick = () => {
    setEditAvatarPopupOpen(true);
  };
  const handleEditProfileClick = () => {
    setEditProfilePopupOpen(true);
  };
  const handleAddPlaceClick = () => {
    setAddPlacePopupOpen(true);
  };

  useEffect(() => {
    if (!loggedIn) return;

    Promise.all([api.getUserInfo(), api.getCardList()])
    .then(([user, cards]) => {
      setCurrentUser(user);
      setCards(cards.reverse());
    })
    .catch((err) => console.log(err));
  }, [loggedIn]);

  useEffect(() => {
    api
      .getUserInfo()
      .then((res) => {
        setEmail(res.email);
        setLoggedIn(true);
        navigate("/");
      })
      .catch((err) => console.log(err));
  }, []);

  const handleLogin = (email, password) => {
    api
      .login(password, email)
      .then(() => {
        setEmail(email);
        setLoggedIn(true);
        navigate("/");
      })
      .catch((err) => console.log(err));
  };

  const handleRegister = (email, password) => {
    setIsLoading(true);
    api
      .register(password, email)
      .then(() => setSuccess(true))
      .catch((err) => {
        setSuccess(false);
        console.log("error", err);
      })
      .finally(() => {
        setInfoTooltipOpen(true);
        setIsLoading(false);
      });
  };

  const handleLogOut = () => {
    api
      .logout()
      .then(() => {
        setLoggedIn(false);
        setCurrentUser({ name: "", about: "", avatar: "" });
      })
      .catch((err) => console.log(err));
  };

  const handleCardLike = (card) => {
    const isLiked = card.likes.some((i) => i === currentUser._id);

    api
      .like(card, isLiked)
      .then((newCard) => {
        setCards((cards) =>
          cards.map((i) => (i._id === card._id ? newCard : i))
        );
      })
      .catch((err) => console.log(err));
  };

  const handleCardDelete = (card) => {
    api
      .deleteCard(card)
      .then(() => {
        setCards((cards) => cards.filter((c) => c._id !== card._id));
      })
      .catch((err) => console.log(err))
      .finally(() => setConnfirmPopupOpen(false))
  };

  const handleConfirmationPopup = (card) => {
    setConnfirmPopupOpen(true);
    setRemoveCard(card);
  };

  useEffect(() => {
    if (!isInfoTooltipOpen && success) navigate("/signin");
  }, [isInfoTooltipOpen]);

  const handleUpdateUser = (data) => {
    api
      .editUserInfo(data)
      .then((res) => setCurrentUser(res))
      .catch((err) => console.log(err))
      .finally(() => closeAllPopups());
  };

  const handleUpdateAvatar = (link) => {
    api
      .editUserAvatar(link)
      .then((res) => setCurrentUser(res))
      .catch((err) => console.log(err))
      .finally(() => closeAllPopups());
  };

  const handleAddPlaceSubmit = (data) => {
    api
      .postNewCard(data)
      .then((newCard) => setCards([newCard, ...cards]))
      .catch((err) => console.log(err))
      .finally(() => closeAllPopups());
  };

  const closeAllPopups = () => {
    setEditProfilePopupOpen(false);
    setEditAvatarPopupOpen(false);
    setAddPlacePopupOpen(false);
    setConnfirmPopupOpen(false);
    setImagePopupOpen(false);
  };

  return (
    <Routes>
      <Route element={<ProtectedRoute onLogin={loggedIn}/>}>
        <Route
          path="/"
          element={
            <CurrentUserContext.Provider value={currentUser}>
              <Header
                link="/signin"
                text="??????????"
                email={email}
                onLogOut={handleLogOut}
              ></Header>

              <Main
                onEditAvatar={handleEditAvatarClick}
                onAddPlace={handleAddPlaceClick}
                onEditProfile={handleEditProfileClick}
                onCardClick={handleCardClick}
                cards={cards}
                onCardLike={handleCardLike}
                onCardDelete={handleConfirmationPopup}
              />

              <Footer />

              <EditProfilePopup
                isOpen={isEditProfilePopupOpen}
                onClose={closeAllPopups}
                onUpdateUser={handleUpdateUser}
              />

              <EditAvatarPopup
                isOpen={isEditAvatarPopupOpen}
                onClose={closeAllPopups}
                onUpdateAvatar={handleUpdateAvatar}
              />

              <AddPlacePopup
                isOpen={isAddPlacePopupOpen}
                onClose={closeAllPopups}
                onAddPlace={handleAddPlaceSubmit}
              />

              <ConfirmPopup
                name="confirm"
                title="???? ???????????????"
                card={removeCard}
                isOpen={isConfirmPopupOpen}
                onCardDelete={handleCardDelete}
                onClose={closeAllPopups}
              />

              <ImagePopup
                card={selectedCard}
                isOpened={isImagePopupOpen}
                onClose={closeAllPopups}
              />
            </CurrentUserContext.Provider>
          }
        />
      </Route>
      <Route
        element={
          <Register
            success={success}
            isOpen={isInfoTooltipOpen}
            onRegister={handleRegister}
            isLoading={isLoading}
            closeInfoTooltip={setInfoTooltipOpen}
          />
        }
        path="/signup"
      />
      <Route element={<Login onLogin={handleLogin} />} path="/signin" />
      <Route element={<NotFound />} path="/*" />
      {/* TODO */}
    </Routes>
  );
}

export default App;
