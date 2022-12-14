import React, { useContext } from 'react';
import { CurrentUserContext } from '../contexts/CurrentUserContext';
import '../index.css';
import Card from './Card';

function Main(props) {
  const { onEditAvatar, onEditProfile, onAddPlace, cards } = props;
  const currentUser = useContext(CurrentUserContext);

  return (
    <main className="content">
      <section className="profile section content__section content__profile">
        <div className="profile__container">
          <div className="profile__another-container">
            <img src={currentUser.avatar} alt="Аватар" className="profile__avatar" />
            <button className="profile__button" aria-label="Нажми чтобы обновить" onClick={onEditAvatar}></button>
          </div>
          <div className="profile__description">
            <h1 className="name profile__title">{currentUser.name}</h1>
            <button className="profile__edit-button" type="button" aria-label="Изменить" onClick={onEditProfile}></button>
            <p className="about profile__subtitle">{currentUser.about}</p>
          </div>
        </div>
        <button className="profile__add-button add-button" type="button" aria-label="Добавить" onClick={onAddPlace}></button>
      </section>
      <section className="elements section content__section">
        {cards.map((card, i) => (<Card card={card} key={cards[i]._id} {...props} />))}
      </section>
    </main>
  );
}

export default Main


